// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/httpapi.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/strings.h"

#define MAX_HOSTNAME_LEN        65
#define TEMP_BUFFER_SIZE        4096
#define TIME_MAX_BUFFER         16

static const char* HTTP_REQUEST_LINE_FMT = "%s %s HTTP/1.1\r\n";
static const char* HTTP_CONTENT_LEN = "Content-Length";
static const char* HTTP_HOST_HEADER = "Host";
static const char* HTTP_CHUNKED_ENCODING_HDR = "Transfer-Encoding: chunked\r\n";
static const char* HTTP_CRLF_VALUE = "\r\n";
static const char* FORMAT_HEX_CHAR = "0x%02x ";

DEFINE_ENUM_STRINGS(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)

typedef enum RESPONSE_MESSAGE_STATE_TAG
{
    state_initial,
    state_status_line,
    state_response_header,
    state_message_body,
    state_message_chunked,
    state_error
} RESPONSE_MESSAGE_STATE;

typedef struct HTTP_RECV_DATA_TAG
{
    int statusCode;
    RESPONSE_MESSAGE_STATE recvState;
    HTTP_HEADERS_HANDLE respHeader;
    BUFFER_HANDLE msgBody;
    size_t totalBodyLen;
    unsigned char* storedBytes;
    size_t storedLen;
    ON_EXECUTE_COMPLETE fn_execute_complete;
    void* execute_ctx;
    bool chunkedReply;
} HTTP_RECV_DATA;

typedef struct HTTP_HANDLE_DATA_TAG
{
    char* hostname;
    char* certificate;
    XIO_HANDLE xio_handle;
    size_t received_bytes_count;
    unsigned char*  received_bytes;
    HTTP_RECV_DATA recvMsg;
    unsigned int is_io_error : 1;
    unsigned int is_connected : 1;
    bool logTrace;
} HTTP_HANDLE_DATA;

static void getLogTime(char* timeResult, size_t len)
{
    if (timeResult != NULL)
    {
        time_t localTime = time(NULL);
        struct tm* tmInfo = localtime(&localTime);
        if (strftime(timeResult, len, "%H:%M:%S", tmInfo) == 0)
        {
            timeResult[0] = '\0';
        }
    }
}

static int ProcessStatusCodeLine(const unsigned char* buffer, size_t len, size_t* position, int* statusLen)
{
    int result = __LINE__;
    size_t index;
    int spaceFound = 0;
    const char* initSpace = NULL;
    char statusCode[4];

    for (index = 0; index < len; index++)
    {
        if (buffer[index] == ' ')
        {
            if (spaceFound == 1)
            {
                strncpy(statusCode, initSpace, 3);
                statusCode[3] = '\0';
            }
            else
            {
                initSpace = (const char*)buffer+index+1;
            }
            spaceFound++;
        }
        else if (buffer[index] == '\n')
        {
            *statusLen = (int)atol(statusCode);
            if (index < len)
            {
                *position = index+1;
            }
            else
            {
                *position = index;
            }
            result = 0;
            break;
        }
    }
    return result;
}

static int ProcessHeaderLine(const unsigned char* buffer, size_t len, size_t* position, HTTP_HEADERS_HANDLE respHeader, size_t* contentLen, bool* isChunked)
{
    int result = __LINE__;
    size_t index;
    const unsigned char* targetPos = buffer;
    bool crlfEncounted = false;
    bool colonEncountered = false;
    char* headerKey = NULL;
    bool continueProcessing = true;

    for (index = 0; index < len && continueProcessing; index++)
    {
        if (buffer[index] == ':' && !colonEncountered)
        {
            colonEncountered = true;
            size_t keyLen = (&buffer[index])-targetPos;
            headerKey = (char*)malloc(keyLen+1);
            memcpy(headerKey, targetPos, keyLen);
            headerKey[keyLen] = '\0';

            targetPos = buffer+index+1;
            crlfEncounted = false;
        }
        else if (buffer[index] == '\r')
        {
            if (headerKey != NULL)
            {
                // Remove leading spaces
                while (*targetPos == 32) { targetPos++; }

                size_t valueLen = (&buffer[index])-targetPos;
                char* headerValue = (char*)malloc(valueLen+1);
                memcpy(headerValue, targetPos, valueLen);
                headerValue[valueLen] = '\0';

                if (HTTPHeaders_AddHeaderNameValuePair(respHeader, headerKey, headerValue) != HTTP_HEADERS_OK)
                {
                    result = __LINE__;
                    continueProcessing = false;
                }
                else
                {
                    if (strcmp(headerKey, HTTP_CONTENT_LEN) == 0)
                    {
                        *isChunked = false;
                        *contentLen = atol(headerValue);
                    }
                    else if (strcmp(headerKey, "Transfer-Encoding") == 0)
                    {
                        *isChunked = true;
                        *contentLen = 0;
                    }
                }
                free(headerKey);
                headerKey = NULL;
                free(headerValue);
            }
        }
        else if (buffer[index] == '\n')
        {
            if (index < len)
            {
                *position = index+1;
            }
            else
            {
                *position = index;
            }
            if (crlfEncounted)
            {
                result = 0;
                break;
            }
            else
            {
                colonEncountered = false;
                crlfEncounted = true;
                targetPos = buffer+index+1;
            }
        }
        else
        {
            crlfEncounted = false;
        }
    }
    if (headerKey != NULL)
    {
        free(headerKey);
    }
    return result;
}

static int ConvertCharToHex(const unsigned char* hexText, size_t len)
{
    int result = 0;
    for (size_t index = 0; index < len; index++)
    {
        int accumulator = 0;
        if (hexText[index] >= 48 && hexText[index] <= 57)
        {
            accumulator = hexText[index] - 48;
        }
        else if (hexText[index] >= 65 && hexText[index] <= 70)
        {
            accumulator = hexText[index] - 55;
        }
        else if (hexText[index] >= 97 && hexText[index] <= 102)
        {
            accumulator = hexText[index] - 87;
        }
        if (index > 0)
        {
            result = result << 4;
        }
        result += accumulator;
    }
    return result;
}


static void on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)context;
    if (http_data != NULL)
    {
        if (open_result == IO_OPEN_OK)
        {
            http_data->is_connected = 1;
            http_data->is_io_error = 0;
        }
        else
        {
            http_data->is_io_error = 1;
        }
    }
}

static void on_bytes_recv(void* context, const unsigned char* buffer, size_t len)
{
    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)context;
    size_t index = 0;
    HTTPAPI_RESULT execute_result;

    if (http_data != NULL && buffer != NULL && len > 0 && http_data->recvMsg.recvState != state_error && http_data->recvMsg.fn_execute_complete != NULL)
    {
        if (http_data->recvMsg.recvState == state_initial)
        {
            if (http_data->recvMsg.respHeader == NULL)
            {
                http_data->recvMsg.respHeader = HTTPHeaders_Alloc();
            }
            if (http_data->recvMsg.msgBody == NULL)
            {
                http_data->recvMsg.msgBody = BUFFER_new();
            }
            http_data->recvMsg.chunkedReply = false;
        }

        if (http_data->recvMsg.storedLen == 0)
        {
            http_data->recvMsg.storedBytes = (unsigned char*)malloc(len);
            memcpy(http_data->recvMsg.storedBytes, buffer, len);
            http_data->recvMsg.storedLen = len;
        }
        else
        {
            size_t newSize = http_data->recvMsg.storedLen+len;
            unsigned char* tmpBuff = (unsigned char*)malloc(newSize);
            if (tmpBuff == NULL)
            {
                LogError("Failure reallocating buffer.");
                http_data->recvMsg.recvState = state_error;
                free(http_data->recvMsg.storedBytes);
                http_data->recvMsg.storedBytes = NULL;
                execute_result = HTTPAPI_ALLOC_FAILED;
            }
            else
            {
                memcpy(tmpBuff, http_data->recvMsg.storedBytes, http_data->recvMsg.storedLen);
                free(http_data->recvMsg.storedBytes);
                http_data->recvMsg.storedBytes = tmpBuff;
                memcpy(http_data->recvMsg.storedBytes+http_data->recvMsg.storedLen, buffer, len);
                http_data->recvMsg.storedLen = newSize;
            }
        }

        if (http_data->recvMsg.recvState == state_initial)
        {
            index = 0;
            int lineComplete = ProcessStatusCodeLine(http_data->recvMsg.storedBytes, http_data->recvMsg.storedLen, &index, &http_data->recvMsg.statusCode);
            if (lineComplete == 0 && http_data->recvMsg.statusCode > 0)
            {
                http_data->recvMsg.recvState = state_status_line;

                // Let's remove the unneccessary bytes
                size_t allocLen = http_data->recvMsg.storedLen-index;
                unsigned char* tmpBuff = (unsigned char*)malloc(allocLen);
                memcpy(tmpBuff, http_data->recvMsg.storedBytes+index, allocLen);
                free(http_data->recvMsg.storedBytes);
                http_data->recvMsg.storedBytes = tmpBuff;
                http_data->recvMsg.storedLen = allocLen;
            }
        }
        if (http_data->recvMsg.recvState == state_status_line)
        {
            // Gather the Header
            index = 0;
            int headerComplete = ProcessHeaderLine(http_data->recvMsg.storedBytes, http_data->recvMsg.storedLen, &index, http_data->recvMsg.respHeader, &http_data->recvMsg.totalBodyLen, &http_data->recvMsg.chunkedReply);
            if (headerComplete == 0)
            {
                if (http_data->recvMsg.totalBodyLen == 0)
                {
                    if (http_data->recvMsg.chunkedReply)
                    {
                        http_data->recvMsg.recvState = state_message_chunked;
                    }
                    else
                    {
                        // Content len is 0 so we are finished with the body
                        execute_result = HTTPAPI_OK;
                        http_data->recvMsg.fn_execute_complete(http_data->recvMsg.execute_ctx, execute_result, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, NULL, 0);
                        http_data->recvMsg.recvState = state_message_body;
                    }
                }
                else
                {
                    http_data->recvMsg.recvState = state_response_header;
                }
            }
            if (index > 0)
            {
                // Let's remove the unneccessary bytes
                size_t allocLen = http_data->recvMsg.storedLen-index;
                unsigned char* tmpBuff = (unsigned char*)malloc(allocLen);
                memcpy(tmpBuff, http_data->recvMsg.storedBytes+index, allocLen);
                free(http_data->recvMsg.storedBytes);
                http_data->recvMsg.storedBytes = tmpBuff;
                http_data->recvMsg.storedLen = allocLen;
            }
        }
        if (http_data->recvMsg.recvState == state_response_header)
        {
            if (http_data->recvMsg.totalBodyLen != 0)
            {
                bool parseSuccess = false;
                if (http_data->recvMsg.storedLen == http_data->recvMsg.totalBodyLen)
                {
                    if (BUFFER_build(http_data->recvMsg.msgBody, http_data->recvMsg.storedBytes, http_data->recvMsg.storedLen) != 0)
                    {
                        http_data->recvMsg.recvState = state_error;
                        parseSuccess = false;
                    }
                    else
                    {
                        parseSuccess = true;
                    }
                }
                else if (http_data->recvMsg.storedLen > http_data->recvMsg.totalBodyLen)
                {
                    http_data->recvMsg.recvState = state_error;
                    parseSuccess = false;
                }
                if (parseSuccess)
                {
                    execute_result = HTTPAPI_OK;
                    http_data->recvMsg.fn_execute_complete(http_data->recvMsg.execute_ctx, execute_result, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, BUFFER_u_char(http_data->recvMsg.msgBody), BUFFER_length(http_data->recvMsg.msgBody) );
                    http_data->recvMsg.recvState = state_message_body;
                }
            }
            else
            {
                // chunked
                /*if (http_data->fnChunkReplyCallback != NULL)
                {
                    http_data->fnChunkReplyCallback((HTTP_CLIENT_HANDLE)data, http_data->userCtx, NULL, 0, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, false);
                }*/
            }
        }
        if (http_data->recvMsg.recvState == state_message_chunked)
        {
            // Chunked reply
            bool crlfEncounted = false;
            size_t chunkLen = 0;
            size_t bytesPos = 0;
            size_t bytesLen = http_data->recvMsg.storedLen;
            const unsigned char* targetPos = http_data->recvMsg.storedBytes;
            const unsigned char* iterator = http_data->recvMsg.storedBytes;

            for (index = 0; index < bytesLen; index++, bytesPos++, iterator++)
            {
                if (*iterator == '\r')
                {
                    size_t hexLen = iterator-targetPos;
                    chunkLen = ConvertCharToHex(targetPos, hexLen);
                    if (chunkLen == 0)
                    {
                        /*if (http_data->fnChunkReplyCallback != NULL)
                        {
                            http_data->fnChunkReplyCallback((HTTP_HANDLE)data, http_data->userCtx, NULL, 0, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, true);
                            http_data->recvMsg.recvState = state_message_body;
                            break;
                        }*/
                    }
                    else if (chunkLen <= http_data->recvMsg.storedLen-index)
                    {
                        // Send the user the chunk
                        if (BUFFER_build(http_data->recvMsg.msgBody, iterator+bytesPos+2, chunkLen) != 0)
                        {
                            http_data->recvMsg.recvState = state_error;
                        }
                        else
                        {
                            /*if (http_data->fnChunkReplyCallback != NULL)
                            {
                                http_data->fnChunkReplyCallback((HTTP_CLIENT_HANDLE)data, http_data->userCtx, BUFFER_u_char(http_data->recvMsg.msgBody), BUFFER_length(http_data->recvMsg.msgBody), http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, false);
                            }*/
                            index += chunkLen+2;
                            if (chunkLen != http_data->recvMsg.storedLen-index)
                            {
                                // Let's remove the unneccessary bytes
                                size_t allocLen = http_data->recvMsg.storedLen-chunkLen;
                                unsigned char* tmpBuff = (unsigned char*)malloc(allocLen);
                                memcpy(tmpBuff, http_data->recvMsg.storedBytes+index, allocLen);
                                free(http_data->recvMsg.storedBytes);
                                http_data->recvMsg.storedBytes = tmpBuff;
                                http_data->recvMsg.storedLen = allocLen;
                                bytesPos = 0;
                            }
                            iterator = targetPos = http_data->recvMsg.storedBytes;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                else if (*iterator == '\n')
                {
                    if (crlfEncounted)
                    {

                    }
                }
            }
        }
        if (http_data->recvMsg.recvState == state_message_body || http_data->recvMsg.recvState == state_error)
        {
            HTTPHeaders_Free(http_data->recvMsg.respHeader);
            http_data->recvMsg.respHeader = NULL;
            BUFFER_delete(http_data->recvMsg.msgBody);
            http_data->recvMsg.msgBody = NULL;
            free(http_data->recvMsg.storedBytes);
            http_data->recvMsg.storedBytes = NULL;
            http_data->recvMsg.storedLen = 0;
        }
    }
}

static void on_io_error(void* context)
{
    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)context;
    if (http_data != NULL)
    {
        http_data->is_io_error = 1;
        LogError("on_io_error: Error signalled by underlying IO");
    }
}

static void on_send_complete(void* context, IO_SEND_RESULT send_result)
{
    if (send_result != IO_SEND_OK)
    {
        HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)context;
        if (http_data != NULL)
        {
            http_data->is_io_error = 1;
        }
    }
}

static int write_http_data(HTTP_HANDLE_DATA* http_data, const unsigned char* writeData, size_t length)
{
    int result;
    if (xio_send(http_data->xio_handle, writeData, length, on_send_complete, http_data) != 0)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
        if (http_data->logTrace)
        {
            char timeResult[TIME_MAX_BUFFER];
            getLogTime(timeResult, TIME_MAX_BUFFER);
            LOG(LOG_TRACE, LOG_LINE, "%s", timeResult);
            for (size_t index = 0; index < length; index++)
            {
                LOG(LOG_TRACE, 0, "0x%02x ", writeData[index]);
            }
        }
    }
    return result;
}

static int write_http_text(HTTP_HANDLE_DATA* http_data, const char* writeText)
{
    int result;
    if (xio_send(http_data->xio_handle, writeText, strlen(writeText), on_send_complete, http_data) != 0)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
        if (http_data->logTrace)
        {
            char timeResult[TIME_MAX_BUFFER];
            getLogTime(timeResult, TIME_MAX_BUFFER);
            LOG(LOG_TRACE, LOG_LINE, "%s", timeResult);
            LOG(LOG_TRACE, LOG_LINE, "%s", writeText);
        }
    }
    return result;
}

static int construct_http_headers(HTTPAPI_REQUEST_TYPE requestType, HTTP_HEADERS_HANDLE httpHeaderHandle, size_t contentLen, STRING_HANDLE buffData, const char* hostname, bool chunkData)
{
    int result;
    size_t headerCnt = 0;
    if (httpHeaderHandle != NULL && HTTPHeaders_GetHeaderCount(httpHeaderHandle, &headerCnt) != HTTP_HEADERS_OK)
    {
        LogError("Failed retrieving http header count.");
        result = __LINE__;
    }
    else
    {
        result = 0;
        bool hostNameFound = false;
        bool contentLenFound = false;
        for (size_t index = 0; index < headerCnt && result == 0; index++)
        {
            char* header;
            if (HTTPHeaders_GetHeader(httpHeaderHandle, index, &header) != HTTP_HEADERS_OK)
            {
                result = __LINE__;
                LogError("Failed in HTTPHeaders_GetHeader");
            }
            else
            {
                size_t dataLen = strlen(header)+2;
                char* sendData = malloc(dataLen+1);
                if (sendData == NULL)
                {
                    result = __LINE__;
                    LogError("Failed in allocating header data");
                }
                else
                {
                    if (strcmp(header, HTTP_CONTENT_LEN) == 0)
                    {
                        contentLenFound = true;
                    }
                    else if (strcmp(header, HTTP_HOST_HEADER) == 0)
                    {
                        hostNameFound = true;
                    }

                    if (snprintf(sendData, dataLen+1, "%s\r\n", header) <= 0)
                    {
                        result = __LINE__;
                        LogError("Failed in constructing header data");
                    }
                    else
                    {
                        if (STRING_concat(buffData, sendData) != 0)
                        {
                            result = __LINE__;
                            LogError("Failed in building header data");
                        }
                    }
                    free(sendData);
                }
                free(header);
            }
        }

        if (result == 0)
        {
            if (chunkData)
            {
                if (STRING_concat(buffData, HTTP_CHUNKED_ENCODING_HDR) != 0)
                {
                    result = __LINE__;
                    LogError("Failed building content len header data");
                }
            }
            else
            {
                if (contentLenFound && (contentLen > 0 || requestType == HTTPAPI_REQUEST_POST) )
                {
                    size_t fmtLen = strlen(HTTP_CONTENT_LEN)+strlen(HTTP_CRLF_VALUE)+10;
                    char* content = malloc(fmtLen+1);
                    if (sprintf(content, "%s: %d%s", HTTP_CONTENT_LEN, (int)contentLen, HTTP_CRLF_VALUE) <= 0)
                    {
                        result = __LINE__;
                        LogError("Failed allocating content len header data");
                    }
                    else
                    {
                        if (STRING_concat(buffData, content) != 0)
                        {
                            result = __LINE__;
                            LogError("Failed building content len header data");
                        }
                    }
                    free(content);
                }
            }

            if (!hostNameFound)
            {
                size_t fmtLen = strlen(HTTP_HOST_HEADER)+strlen(HTTP_CRLF_VALUE)+strlen(hostname)+2;
                char* content = malloc(fmtLen+1);
                if (sprintf(content, "%s: %s%s", HTTP_HOST_HEADER, hostname, HTTP_CRLF_VALUE) <= 0)
                {
                    result = __LINE__;
                    LogError("Failed allocating content len header data");
                }
                else
                {
                    if (STRING_concat(buffData, content) != 0)
                    {
                        result = __LINE__;
                        LogError("Failed building content len header data");
                    }
                }
                free(content);
            }


            if (STRING_concat(buffData, "\r\n") != 0)
            {
                result = __LINE__;
                LogError("Failed sending header finalization data");
            }
        }
    }
    return result;
}

static STRING_HANDLE build_http_request(HTTPAPI_REQUEST_TYPE requestType, const char* relativePath, HTTP_HEADERS_HANDLE httpHeadersHandle, size_t contentLength, const char* hostname, bool chunkData)
{
    STRING_HANDLE result;

    const char* method = (requestType == HTTPAPI_REQUEST_GET) ? "GET"
        : (requestType == HTTPAPI_REQUEST_OPTIONS) ? "OPTIONS"
        : (requestType == HTTPAPI_REQUEST_POST) ? "POST"
        : (requestType == HTTPAPI_REQUEST_PUT) ? "PUT"
        : (requestType == HTTPAPI_REQUEST_DELETE) ? "DELETE"
        : (requestType == HTTPAPI_REQUEST_PATCH) ? "PATCH"
        : NULL;
    if (method == NULL)
    {
        LogError("Invalid request method specified");
        result = NULL;
    }
    else
    {
        size_t buffLen = strlen(HTTP_REQUEST_LINE_FMT)+strlen(method)+strlen(relativePath);
        char* request = malloc(buffLen+1);
        if (request == NULL)
        {
            result = NULL;
            LogError("Failure allocating Request data");
        }
        else
        {
            if (snprintf(request, buffLen+1, HTTP_REQUEST_LINE_FMT, method, relativePath) <= 0)
            {
                result = NULL;
                LogError("Failure writing request buffer");
            }
            else
            {
                result = STRING_construct(request);
                if (result == NULL)
                {
                    LogError("Failure creating buffer object");
                }
                else if (construct_http_headers(requestType, httpHeadersHandle, contentLength, result, hostname, chunkData) != 0)
                {
                    STRING_delete(result);
                    result = NULL;
                }
            }
            free(request);
        }
    }
    return result;
}

static int send_http_data(HTTP_HANDLE_DATA* http_data, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath,
    HTTP_HEADERS_HANDLE httpHeadersHandle, size_t contentLength, bool sendChunked)
{
    int result;
    STRING_HANDLE httpData = build_http_request(requestType, relativePath, httpHeadersHandle, contentLength, http_data->hostname, sendChunked);
    if (httpData == NULL)
    {
        result = __LINE__;
    }
    else
    {
        if (write_http_text(http_data, STRING_c_str(httpData)) != 0)
        {
            result = __LINE__;
            LogError("Failure writing request buffer");
        }
        else
        {
            result = 0;
        }
        STRING_delete(httpData);
    }
    return result;
}

HTTP_HANDLE HTTPAPI_CreateConnection(XIO_HANDLE xio, const char* hostName)
{
    HTTP_HANDLE_DATA* http_data = NULL;
    if (hostName == NULL || xio == NULL)
    {
        LogInfo("Failure: invalid parameter was NULL");
    }
    else if (strlen(hostName) > MAX_HOSTNAME_LEN)
    {
        LogInfo("Failure: Host name length is too long");
    }
    else
    {
        http_data = (HTTP_HANDLE_DATA*)malloc(sizeof(HTTP_HANDLE_DATA));
        if (http_data == NULL)
        {
            LogInfo("failed allocating HTTP_HANDLE_DATA");
        }
        else
        {
            http_data->xio_handle = xio;

            if (mallocAndStrcpy_s(&http_data->hostname, hostName) != 0)
            {
                LogError("Failure opening xio connection");
                free(http_data);
                http_data = NULL;
            }
            else if (xio_open(http_data->xio_handle, on_io_open_complete, http_data, on_bytes_recv, http_data, on_io_error, http_data) != 0)
            {
                LogError("Failure allocating hostname");
                free(http_data->hostname);
                free(http_data);
                http_data = NULL;
            }
            else
            {
                http_data->is_connected = 0;
                http_data->is_io_error = 0;
                http_data->received_bytes_count = 0;
                http_data->received_bytes = NULL;
                http_data->certificate = NULL;
                memset(&http_data->recvMsg, 0, sizeof(HTTP_RECV_DATA) );
                http_data->recvMsg.recvState = state_initial;
                http_data->recvMsg.chunkedReply = false;
            }
        }
    }
    return (HTTP_HANDLE)http_data;
}

void HTTPAPI_CloseConnection(HTTP_HANDLE handle)
{
    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
    if (http_data != NULL)
    {
        if (http_data->xio_handle != NULL)
        {
            (int)xio_close(http_data->xio_handle, NULL, NULL);
        }
        if (http_data->certificate)
        {
            free(http_data->certificate);
        }
        if (http_data->hostname)
        {
            free(http_data->hostname);
        }
        free(http_data);
    }
}

//Note: This function assumes that "Host:" and "Content-Length:" headers are setup
//      by the caller of HTTPAPI_ExecuteRequest() (which is true for httptransport.c).
HTTPAPI_RESULT HTTPAPI_ExecuteRequest(HTTP_HANDLE handle, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath,
    HTTP_HEADERS_HANDLE httpHeadersHandle, const unsigned char* content,
    size_t contentLength, unsigned int* statusCode,
    HTTP_HEADERS_HANDLE responseHeadersHandle, BUFFER_HANDLE responseContent)
{
    (void)handle;
    (void)requestType;
    (void)relativePath;
    (void)httpHeadersHandle;
    (void)content;
    (void)contentLength;
    (void)statusCode;
    (void)responseHeadersHandle;(void)responseContent;

    HTTPAPI_RESULT result = HTTPAPI_ERROR;
    return result;
}

HTTPAPI_RESULT HTTPAPI_ExecuteRequestAsync(HTTP_HANDLE handle, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath, HTTP_HEADERS_HANDLE httpHeadersHandle,
    const unsigned char* content, size_t contentLength, ON_EXECUTE_COMPLETE on_execute_complete, void* callback_context)
{
    HTTPAPI_RESULT result;

    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;

    if (http_data == NULL || relativePath == NULL ||
        (content != NULL && contentLength == 0) || (content == NULL && contentLength != 0))
    {
        result = HTTPAPI_INVALID_ARG;
    }
    else if (http_data->recvMsg.recvState != state_initial)
    {
        result = HTTPAPI_ALREADY_INIT;
    }
    else
    {
        http_data->recvMsg.fn_execute_complete = on_execute_complete;
        http_data->recvMsg.execute_ctx = callback_context;
        if (send_http_data(http_data, requestType, relativePath, httpHeadersHandle, contentLength, false) != 0)
        {
            result = HTTPAPI_ERROR;
        }
        else
        {
            if (content != NULL && contentLength != 0)
            {
                if (write_http_data(http_data, content, contentLength) != 0)
                {
                    LogError("Failure writing content buffer");
                    HTTPHeaders_Free(http_data->recvMsg.respHeader);
                    http_data->recvMsg.respHeader = NULL;
                    BUFFER_delete(http_data->recvMsg.msgBody);
                    http_data->recvMsg.msgBody = NULL;
                    result = HTTPAPI_ERROR;
                }
                else
                {
                    result = HTTPAPI_OK;
                }
            }
            else
            {
                result = HTTPAPI_OK;
            }
        }
    }
    return result;
}

void HTTPAPI_DoWork(HTTP_HANDLE handle)
{
    if (handle != NULL)
    {
        HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
        xio_dowork(http_data->xio_handle);
    }
}

HTTPAPI_RESULT HTTPAPI_SetOption(HTTP_HANDLE handle, const char* optionName, const void* value)
{
    HTTPAPI_RESULT result;
    if (handle == NULL || optionName == NULL || value == NULL)
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("invalid parameter (NULL) passed to HTTPAPI_SetOption");
    }
    else if (strcmp("TrustedCerts", optionName) == 0)
    {
        HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
        if (http_data->certificate)
        {
            free(http_data->certificate);
        }

        int len = strlen((char*)value);
        http_data->certificate = (char*)malloc(len + 1);
        if (http_data->certificate == NULL)
        {
            result = HTTPAPI_ERROR;
            LogError("unable to allocate certificate memory in HTTPAPI_SetOption");
        }
        else
        {
            (void)strcpy(http_data->certificate, (const char*)value);
            result = HTTPAPI_OK;
        }
    }
    else if (strcmp("logtrace", optionName) == 0)
    {
        HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
        http_data->logTrace = *((bool*)value);
        result = HTTPAPI_OK;
    }
    else
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("unknown option %s", optionName);
    }
    return result;
}

HTTPAPI_RESULT HTTPAPI_CloneOption(const char* optionName, const void* value, const void** savedValue)
{
    HTTPAPI_RESULT result;
    if (optionName == NULL || value == NULL || savedValue == NULL)
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("invalid argument(NULL) passed to HTTPAPI_CloneOption");
    }
    else if (strcmp("TrustedCerts", optionName) == 0)
    {
        size_t certLen = strlen((const char*)value);
        char* tempCert = (char*)malloc(certLen+1);
        if (tempCert == NULL)
        {
            result = HTTPAPI_ALLOC_FAILED;
            LogError("unable to allocate certificate memory in HTTPAPI_CloneOption");
        }
        else
        {
            (void)strcpy(tempCert, (const char*)value);
            *savedValue = tempCert;
            result = HTTPAPI_OK;
        }
    }
    else if (strcmp("logtrace", optionName) == 0)
    {
        bool* tempLogTrace = malloc(sizeof(bool) );
        if (tempLogTrace == NULL)
        {
            result = HTTPAPI_ALLOC_FAILED;
            LogError("unable to allocate logtrace in HTTPAPI_CloneOption");
        }
        else
        {
            *savedValue = tempLogTrace;
            result = HTTPAPI_OK;
        }
    }
    else
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("unknown option %s", optionName);
    }
    return result;
}

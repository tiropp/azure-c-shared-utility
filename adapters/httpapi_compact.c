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
#include "azure_c_shared_utility/httpapi.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/strings.h"
//#include <string.h>

#define MAX_HOSTNAME_LEN        65
#define TEMP_BUFFER_SIZE        4096
#define TIME_MAX_BUFFER         16

static const char* HTTP_REQUEST_LINE_FMT = "%s %s HTTP/1.1\r\n";
static const char* HTTP_CONTENT_LEN = "Content-Length";
static const char* HTTP_CHUNKED_ENCODING_HDR = "Transfer-Encoding: chunked\r\n";
static const char* HTTP_CRLF_VALUE = "\r\n";
static const char* FORMAT_HEX_CHAR = "0x%02x ";

#define CHAR_COUNT(A)   (sizeof(A) - 1)

DEFINE_ENUM_STRINGS(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)

typedef enum SEND_ALL_RESULT_TAG
{
    SEND_ALL_RESULT_NOT_STARTED,
    SEND_ALL_RESULT_PENDING,
    SEND_ALL_RESULT_OK,
    SEND_ALL_RESULT_ERROR
} SEND_ALL_RESULT;

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
    SEND_ALL_RESULT send_all_result;

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

    if (http_data != NULL && buffer != NULL && len > 0 && http_data->recvMsg.recvState != state_error)
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
                        http_data->recvMsg.fn_execute_complete(http_data->recvMsg.execute_ctx, execute_result, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, NULL);
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
                    http_data->recvMsg.fn_execute_complete(http_data->recvMsg.execute_ctx, execute_result, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, NULL);
                    //http_data->fnReplyCallback((HTTP_CLIENT_HANDLE)data, http_data->userCtx, BUFFER_u_char(http_data->recvMsg.msgBody), BUFFER_length(http_data->recvMsg.msgBody), http_data->recvMsg.statusCode, http_data->recvMsg.respHeader);
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
            LOG(LOG_INFO, LOG_LINE, "%s", timeResult);
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
            LOG(LOG_INFO, LOG_LINE, "%s", timeResult);
            LOG(LOG_TRACE, LOG_LINE, "%s", writeText);
        }
    }
    return result;
}

static int construct_http_headers(HTTP_HEADERS_HANDLE httpHeaderHandle, size_t contentLen, STRING_HANDLE buffData, bool chunkData)
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

                    }
                    else if (strcmp(header, HTTP_CONTENT_LEN) == 0)
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
                size_t fmtLen = strlen(HTTP_CONTENT_LEN)+strlen(HTTP_CRLF_VALUE)+8;
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

            if (STRING_concat(buffData, "\r\n") != 0)
            {
                result = __LINE__;
                LogError("Failed sending header finalization data");
            }
        }
    }
    return result;
}

static STRING_HANDLE build_http_request(HTTPAPI_REQUEST_TYPE requestType, const char* relativePath, HTTP_HEADERS_HANDLE httpHeadersHandle, size_t contentLength, bool chunkData)
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
                else if (construct_http_headers(httpHeadersHandle, contentLength, result, chunkData) != 0)
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
    STRING_HANDLE httpData = build_http_request(requestType, relativePath, httpHeadersHandle, contentLength, sendChunked);
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

HTTP_HANDLE HTTPAPI_CreateConnection(const char* hostName)
{
    (void)hostName;
    return NULL;
}

HTTP_HANDLE HTTPAPI_CreateConnection_new(XIO_HANDLE io_handle, const char* hostName)
{
    HTTP_HANDLE_DATA* http_data = NULL;
    if (hostName == NULL || io_handle == NULL)
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
            http_data->xio_handle = io_handle;

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
                //handle->send_all_result = SEND_ALL_RESULT_NOT_STARTED;
                http_data->certificate = NULL;
                http_data->recvMsg.recvState = state_initial;
                http_data->recvMsg.statusCode = 0;
                http_data->recvMsg.totalBodyLen = 0;
                http_data->recvMsg.storedBytes = NULL;
                http_data->recvMsg.storedLen = 0;;
                http_data->recvMsg.fn_execute_complete = NULL;
                http_data->recvMsg.execute_ctx = NULL;
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
    /*size_t  headersCount;
    char    buf[TEMP_BUFFER_SIZE];
    int     ret;
    size_t  bodyLength = 0;
    bool    chunked = false;
    const unsigned char* receivedContent;

    const char* method = (requestType == HTTPAPI_REQUEST_GET) ? "GET"
        : (requestType == HTTPAPI_REQUEST_POST) ? "POST"
        : (requestType == HTTPAPI_REQUEST_PUT) ? "PUT"
        : (requestType == HTTPAPI_REQUEST_DELETE) ? "DELETE"
        : (requestType == HTTPAPI_REQUEST_PATCH) ? "PATCH"
        : NULL;

    if (handle == NULL ||
        relativePath == NULL ||
        httpHeadersHandle == NULL ||
        method == NULL ||
        HTTPHeaders_GetHeaderCount(httpHeadersHandle, &headersCount) != HTTP_HEADERS_OK)
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }

    HTTP_HANDLE_DATA* httpHandle = (HTTP_HANDLE_DATA*)handle;

    if (handle->is_connected == 0)
    {
        // Load the certificate
        if ((httpHandle->certificate != NULL) &&
            (xio_setoption(httpHandle->xio_handle, "TrustedCerts", httpHandle->certificate) != 0))
        {
            result = HTTPAPI_ERROR;
            LogError("Could not load certificate (result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }

        // Make the connection
        if (xio_open(httpHandle->xio_handle, on_io_open_complete, httpHandle, on_bytes_received, httpHandle, on_io_error, httpHandle) != 0)
        {
            result = HTTPAPI_ERROR;
            LogError("Could not connect (result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }

        while (1)
        {
            xio_dowork(httpHandle->xio_handle);
            if ((handle->is_connected == 1) ||
                (handle->is_io_error == 1))
            {
                break;
            }

            ThreadAPI_Sleep(1);
        }
    }

    //Send request
    if ((ret = snprintf(buf, sizeof(buf), "%s %s HTTP/1.1\r\n", method, relativePath)) < 0
        || ret >= sizeof(buf))
    {
        result = HTTPAPI_STRING_PROCESSING_ERROR;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }
    if (conn_send_all(httpHandle, buf, strlen(buf)) < 0)
    {
        result = HTTPAPI_SEND_REQUEST_FAILED;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }

    //Send default headers
    for (size_t i = 0; i < headersCount; i++)
    {
        char* header;
        if (HTTPHeaders_GetHeader(httpHeadersHandle, i, &header) != HTTP_HEADERS_OK)
        {
            result = HTTPAPI_HTTP_HEADERS_FAILED;
            LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }
        if (conn_send_all(httpHandle, header, strlen(header)) < 0)
        {
            result = HTTPAPI_SEND_REQUEST_FAILED;
            LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            free(header);
            goto exit;
        }
        if (conn_send_all(httpHandle, "\r\n", 2) < 0)
        {
            result = HTTPAPI_SEND_REQUEST_FAILED;
            LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            free(header);
            goto exit;
        }
        free(header);
    }

    //Close headers
    if (conn_send_all(httpHandle, "\r\n", 2) < 0)
    {
        result = HTTPAPI_SEND_REQUEST_FAILED;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }

    //Send data (if available)
    if (content && contentLength > 0)
    {
        if (conn_send_all(httpHandle, (char*)content, contentLength) < 0)
        {
            result = HTTPAPI_SEND_REQUEST_FAILED;
            LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }
    }

    //Receive response
    if (readLine(httpHandle, buf, sizeof(buf)) < 0)
    {
        result = HTTPAPI_READ_DATA_FAILED;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }

    //Parse HTTP response
    if (sscanf(buf, "HTTP/%*d.%*d %d %*[^\r\n]", &ret) != 1)
    {
        //Cannot match string, error
        LogInfo("HTTPAPI_ExecuteRequest::Not a correct HTTP answer=%s", buf);
        result = HTTPAPI_READ_DATA_FAILED;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }
    if (statusCode)
        *statusCode = ret;

    //Read HTTP response headers
    if (readLine(httpHandle, buf, sizeof(buf)) < 0)
    {
        result = HTTPAPI_READ_DATA_FAILED;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }

    while (buf[0])
    {
        const char ContentLength[] = "content-length:";
        const char TransferEncoding[] = "transfer-encoding:";

        if (my_strnicmp(buf, ContentLength, CHAR_COUNT(ContentLength)) == 0)
        {
            if (sscanf(buf + CHAR_COUNT(ContentLength), " %d", &bodyLength) != 1)
            {
                result = HTTPAPI_READ_DATA_FAILED;
                LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                goto exit;
            }
        }
        else if (my_strnicmp(buf, TransferEncoding, CHAR_COUNT(TransferEncoding)) == 0)
        {
            const char* p = buf + CHAR_COUNT(TransferEncoding);
            while (isspace(*p)) p++;
            if (my_stricmp(p, "chunked") == 0)
                chunked = true;
        }

        char* whereIsColon = strchr((char*)buf, ':');
        if (whereIsColon && responseHeadersHandle != NULL)
        {
            *whereIsColon = '\0';
            HTTPHeaders_AddHeaderNameValuePair(responseHeadersHandle, buf, whereIsColon + 1);
        }

        if (readLine(httpHandle, buf, sizeof(buf)) < 0)
        {
            result = HTTPAPI_READ_DATA_FAILED;
            LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }
    }

    //Read HTTP response body
    if (!chunked)
    {
        if (bodyLength)
        {
            if (responseContent != NULL)
            {
                if (BUFFER_pre_build(responseContent, bodyLength) != 0)
                {
                    result = HTTPAPI_ALLOC_FAILED;
                    LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                }
                else if (BUFFER_content(responseContent, &receivedContent) != 0)
                {
                    (void)BUFFER_unbuild(responseContent);

                    result = HTTPAPI_ALLOC_FAILED;
                    LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                }

                if (readChunk(httpHandle, (char*)receivedContent, bodyLength) < 0)
                {
                    result = HTTPAPI_READ_DATA_FAILED;
                    LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                    goto exit;
                }
                else
                {
                    result = HTTPAPI_OK;
                }
            }
            else
            {
                (void)skipN(httpHandle, bodyLength, buf, sizeof(buf));
                result = HTTPAPI_OK;
            }
        }
        else
        {
            result = HTTPAPI_OK;
        }
    }
    else
    {
        size_t size = 0;
        result = HTTPAPI_OK;
        for (;;)
        {
            int chunkSize;
            if (readLine(httpHandle, buf, sizeof(buf)) < 0)    // read [length in hex]/r/n
            {
                result = HTTPAPI_READ_DATA_FAILED;
                LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                goto exit;
            }
            if (sscanf(buf, "%x", &chunkSize) != 1)     // chunkSize is length of next line (/r/n is not counted)
            {
                //Cannot match string, error
                result = HTTPAPI_RECEIVE_RESPONSE_FAILED;
                LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                goto exit;
            }

            if (chunkSize == 0)
            {
                // 0 length means next line is just '\r\n' and end of chunks
                if (readChunk(httpHandle, (char*)buf, 2) < 0
                    || buf[0] != '\r' || buf[1] != '\n') // skip /r/n
                {
                    (void)BUFFER_unbuild(responseContent);

                    result = HTTPAPI_READ_DATA_FAILED;
                    LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                    goto exit;
                }
                break;
            }
            else
            {
                if (responseContent != NULL)
                {
                    if (BUFFER_enlarge(responseContent, chunkSize) != 0)
                    {
                        (void)BUFFER_unbuild(responseContent);

                        result = HTTPAPI_ALLOC_FAILED;
                        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                    }
                    else if (BUFFER_content(responseContent, &receivedContent) != 0)
                    {
                        (void)BUFFER_unbuild(responseContent);

                        result = HTTPAPI_ALLOC_FAILED;
                        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                    }

                    if (readChunk(httpHandle, (char*)receivedContent + size, chunkSize) < 0)
                    {
                        result = HTTPAPI_READ_DATA_FAILED;
                        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                        goto exit;
                    }
                }
                else
                {
                    if (skipN(httpHandle, chunkSize, buf, sizeof(buf)) < 0)
                    {
                        result = HTTPAPI_READ_DATA_FAILED;
                        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                        goto exit;
                    }
                }

                if (readChunk(httpHandle, (char*)buf, 2) < 0
                    || buf[0] != '\r' || buf[1] != '\n') // skip /r/n
                {
                    result = HTTPAPI_READ_DATA_FAILED;
                    LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                    goto exit;
                }
                size += chunkSize;
            }
        }

    }

exit:
    if ((handle != NULL) &&
        (handle->is_io_error != 0))
    {
        xio_close(handle->xio_handle, NULL, NULL);
        handle->is_connected = 0;
    }*/

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

/*static int my_strnicmp(const char* s1, const char* s2, size_t n)
{
    size_t i;
    int result = 0;

    for (i = 0; i < n; i++)
    {
        // compute the difference between the chars
        result = tolower(s1[i]) - tolower(s2[i]);

        // break if we have a difference ... 
        if ((result != 0) ||
            // ... or if we got to the end of one the strings 
            (s1[i] == '\0') || (s2[i] == '\0'))
        {
            break;
        }
    }

    return result;
}

static int my_stricmp(const char* s1, const char* s2)
{
    size_t i = 0;

    while ((s1[i] != '\0') && (s2[i] != '\0'))
    {
        // break if we have a difference ...
        if (tolower(s1[i]) != tolower(s2[i]))
        {
            break;
        }

        i++;
    }

    // if we broke because we are at end of string this will yield 0
    // if we broke because there was a difference this will yield non-zero
    return tolower(s1[i]) - tolower(s2[i]);
}

static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    HTTP_HANDLE_DATA* h = (HTTP_HANDLE_DATA*)context;

    // Here we got some bytes so we'll buffer them so the receive functions can consumer it
    unsigned char* new_received_bytes = (unsigned char*)realloc(h->received_bytes, h->received_bytes_count + size);
    if (new_received_bytes == NULL)
    {
        h->is_io_error = 1;
        LogError("on_bytes_received: Error allocating memory for received data");
    }
    else
    {
        h->received_bytes = new_received_bytes;
        (void)memcpy(h->received_bytes + h->received_bytes_count, buffer, size);
        h->received_bytes_count += size;
    }
}

static int conn_receive(HTTP_HANDLE_DATA* http_instance, char* buffer, int count)
{
    int result = 0;

    if (count < 0)
    {
        result = -1;
    }
    else
    {
        while (result < count)
        {
            xio_dowork(http_instance->xio_handle);

            // if any error was detected while receiving then simply break and report it
            if (http_instance->is_io_error != 0)
            {
                result = -1;
                break;
            }

            if (http_instance->received_bytes_count >= (size_t)count)
            {
                // Consuming bytes from the receive buffer 
                (void)memcpy(buffer, http_instance->received_bytes, count);
                (void)memmove(http_instance->received_bytes, http_instance->received_bytes + count, http_instance->received_bytes_count - count);
                http_instance->received_bytes_count -= count;

                // we're not reallocating at each consumption so that we don't trash due to byte by byte consumption
                if (http_instance->received_bytes_count == 0)
                {
                    free(http_instance->received_bytes);
                    http_instance->received_bytes = NULL;
                }

                result = count;
                break;
            }

            ThreadAPI_Sleep(1);
        }
    }

    return result;
}

static void on_send_complete(void* context, IO_SEND_RESULT send_result)
{
    // If a send is complete we'll simply signal this by changing the send all state
    HTTP_HANDLE_DATA* http_instance = (HTTP_HANDLE_DATA*)context;
    if (send_result == IO_SEND_OK)
    {
        http_instance->send_all_result = SEND_ALL_RESULT_OK;
    }
    else
    {
        http_instance->send_all_result = SEND_ALL_RESULT_ERROR;
    }
}

static int conn_send_all(HTTP_HANDLE_DATA* http_instance, char* buffer, int count)
{
    int result;

    if (count < 0)
    {
        result = -1;
    }
    else
    {
        http_instance->send_all_result = SEND_ALL_RESULT_PENDING;
        if (xio_send(http_instance->xio_handle, buffer, count, on_send_complete, http_instance) != 0)
        {
            result = -1;
        }
        else
        {
            // We have to loop in here until all bytes are sent or we encounter an error.
            while (1)
            {
                xio_dowork(http_instance->xio_handle);

                // If we got an error signalled from the underlying IO we simply report it up
                if (http_instance->is_io_error)
                {
                    http_instance->send_all_result = SEND_ALL_RESULT_ERROR;
                    break;
                }

                if (http_instance->send_all_result != SEND_ALL_RESULT_PENDING)
                {
                    break;
                }

                // We yield the CPU for a bit so others can do their work
                ThreadAPI_Sleep(1);
            }

            // The send_all_result indicates what is the status for the send operation.
            //   Not started - means nothing should happen since no send was started
            //   Pending - a send was started, but it is still being carried out 
            //   Ok - Send complete
            //   Error - error
            switch (http_instance->send_all_result)
            {
                default:
                case SEND_ALL_RESULT_NOT_STARTED:
                    result = -1;
                    break;

                case SEND_ALL_RESULT_OK:
                    result = count;
                    break;

                case SEND_ALL_RESULT_ERROR:
                    result = -1;
                    break;
            }
        }
    }

    return result;
}

static int readLine(HTTP_HANDLE_DATA* http_instance, char* buf, const size_t size)
{
    // reads until \r\n is encountered. writes in buf all the characters
    char* p = buf;
    char  c;
    if (conn_receive(http_instance, &c, 1) < 0)
        return -1;
    while (c != '\r') {
        if ((p - buf + 1) >= (int)size)
            return -1;
        *p++ = c;
        if (conn_receive(http_instance, &c, 1) < 0)
            return -1;
    }
    *p = 0;
    if (conn_receive(http_instance, &c, 1) < 0 || c != '\n') // skip \n
        return -1;
    return p - buf;
}

static int readChunk(HTTP_HANDLE_DATA* http_instance, char* buf, size_t size)
{
    size_t cur, offset;

    // read content with specified length, even if it is received
    // only in chunks due to fragmentation in the networking layer.
    // returns -1 in case of error.
    offset = 0;
    while (size > 0)
    {
        cur = conn_receive(http_instance, buf + offset, size);

        // end of stream reached
        if (cur == 0)
            return offset;

        // read cur bytes (might be less than requested)
        size -= cur;
        offset += cur;
    }

    return offset;
}

static int skipN(HTTP_HANDLE_DATA* http_instance, size_t n, char* buf, size_t size)
{
    size_t org = n;
    // read and abandon response content with specified length
    // returns -1 in case of error.
    while (n > size)
    {
        if (readChunk(http_instance, (char*)buf, size) < 0)
            return -1;

        n -= size;
    }

    if (readChunk(http_instance, (char*)buf, n) < 0)
        return -1;

    return org;
}*/

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

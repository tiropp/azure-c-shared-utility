// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/httpapi.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/constbuffer.h"

#define MAX_HOSTNAME_LEN        65
#define TIME_MAX_BUFFER         16
#define HTTP_SECURE_PORT        443
#define HTTP_DEFAULT_PORT       80

static const char* HTTP_PREFIX = "http://";
static const char* HTTP_PREFIX_SECURE = "https://";

static const char* HTTP_REQUEST_LINE_FMT = "%s %s%s%s HTTP/1.1\r\n";
static const char* HTTP_REQUEST_LINE_AUTHORITY_FMT = "%s %s%s:%d%s HTTP/1.1\r\n";
static const char* HTTP_CONTENT_LEN = "Content-Length";
static const char* HTTP_HOST_HEADER = "Host";
static const char* HTTP_CHUNKED_ENCODING_HDR = "Transfer-Encoding: chunked\r\n";
static const char* HTTP_CRLF_VALUE = "\r\n";
static const char* FORMAT_HEX_CHAR = "0x%02x ";

DEFINE_ENUM_STRINGS(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)

typedef enum RESPONSE_MESSAGE_STATE_TAG
{
    state_complete,
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
    HTTPAPI_REQUEST_TYPE requestType;
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
    int http_port;
    XIO_HANDLE xio_handle;
    size_t received_bytes_count;
    unsigned char*  received_bytes;
    HTTP_RECV_DATA recvMsg;
    unsigned int is_io_error : 1;
    unsigned int is_connected : 1;
    bool logTrace;
} HTTP_HANDLE_DATA;

static void get_log_time(char* timeResult, size_t len)
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

static int process_status_line(HTTP_RECV_DATA* recv_data, size_t* position)
{
    int result = __LINE__;
    size_t index;
    int spaceFound = 0;
    const char* initSpace = NULL;
    char statusCode[4];

    for (index = 0; index < recv_data->storedLen; index++)
    {
        if (recv_data->storedBytes[index] == ' ')
        {
            if (spaceFound == 1)
            {
                if (strncpy(statusCode, initSpace, 3) == NULL)
                {
                    LogError("Failure copying statuc code .");
                    recv_data->recvState = state_error;
                    result = __LINE__;
                    break;
                }
                else
                {
                    statusCode[3] = '\0';
                }
            }
            else
            {
                initSpace = (const char*)recv_data->storedBytes+index+1;
            }
            spaceFound++;
        }
        else if (recv_data->storedBytes[index] == '\n')
        {
            recv_data->statusCode = (int)atol(statusCode);
            if (index < recv_data->storedLen)
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

static int process_header_line(HTTP_RECV_DATA* recv_data, size_t* position)
{
    int result = __LINE__;
    size_t index;
    const unsigned char* targetPos = recv_data->storedBytes;
    bool crlfEncounted = false;
    bool colonEncountered = false;
    char* headerKey = NULL;
    bool continueProcessing = true;

    for (index = 0; index < recv_data->storedLen && continueProcessing; index++)
    {
        if (recv_data->storedBytes[index] == ':' && !colonEncountered)
        {
            colonEncountered = true;
            size_t keyLen = (&recv_data->storedBytes[index])-targetPos;
            headerKey = (char*)malloc(keyLen+1);
            if (headerKey == NULL)
            {
                LogError("Failure allocating header memory");
                recv_data->recvState = state_error;
                result = __LINE__;
            }
            else
            {
                memcpy(headerKey, targetPos, keyLen);
                headerKey[keyLen] = '\0';

                targetPos = recv_data->storedBytes+index+1;
                crlfEncounted = false;
            }
        }
        else if (recv_data->storedBytes[index] == '\r')
        {
            if (headerKey != NULL)
            {
                // Remove leading spaces
                while (*targetPos == 32) { targetPos++; }

                size_t valueLen = (&recv_data->storedBytes[index])-targetPos;
                char* headerValue = (char*)malloc(valueLen+1);
                if (headerValue == NULL)
                {
                    LogError("Failure allocating header memory");
                    recv_data->recvState = state_error;
                    result = __LINE__;
                }
                else
                {
                    memcpy(headerValue, targetPos, valueLen);
                    headerValue[valueLen] = '\0';

                    if (HTTPHeaders_AddHeaderNameValuePair(recv_data->respHeader, headerKey, headerValue) != HTTP_HEADERS_OK)
                    {
                        LogError("Failure adding header value");
                        result = __LINE__;
                        continueProcessing = false;
                        recv_data->recvState = state_error;
                    }
                    else
                    {
                        if (strcmp(headerKey, HTTP_CONTENT_LEN) == 0)
                        {
                            recv_data->chunkedReply = false;
                            recv_data->totalBodyLen = atol(headerValue);
                        }
                        else if (strcmp(headerKey, "Transfer-Encoding") == 0)
                        {
                            recv_data->chunkedReply = true;
                            recv_data->totalBodyLen = 0;
                        }
                    }
                    free(headerKey);
                    headerKey = NULL;
                    free(headerValue);
                }
            }
        }
        else if (recv_data->storedBytes[index] == '\n')
        {
            if (index < recv_data->storedLen)
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
                targetPos = recv_data->storedBytes+index+1;
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

static int convert_char_to_hex(const unsigned char* hexText, size_t len)
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

            if (http_data->logTrace)
            {
                char timeResult[TIME_MAX_BUFFER];
                get_log_time(timeResult, TIME_MAX_BUFFER);
                LOG(LOG_TRACE, 0, "<- %s\r\n", timeResult);
            }
        }

        if (http_data->logTrace)
        {
            for (size_t testindex = 0; testindex < len; testindex++)
            {
                LOG(LOG_TRACE, 0, "%c", buffer[testindex]);
            }
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
            int lineComplete = process_status_line(&http_data->recvMsg, &index);
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
            int headerComplete = process_header_line(&http_data->recvMsg, &index);
            if (headerComplete == 0)
            {
                if (http_data->recvMsg.totalBodyLen == 0 || http_data->recvMsg.requestType == HTTPAPI_REQUEST_HEAD)
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
                    CONSTBUFFER_HANDLE response = CONSTBUFFER_CreateFromBuffer(http_data->recvMsg.msgBody);
                    if (response == NULL)
                    {
                        http_data->recvMsg.recvState = state_error;
                        parseSuccess = false;
                    }
                    else
                    {
                        execute_result = HTTPAPI_OK;
                        http_data->recvMsg.fn_execute_complete(http_data->recvMsg.execute_ctx, execute_result, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, response);
                        http_data->recvMsg.recvState = state_message_body;
                        CONSTBUFFER_Destroy(response);
                    }
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
        /*if (http_data->recvMsg.recvState == state_message_chunked)
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
                    chunkLen = convert_char_to_hex(targetPos, hexLen);
                    if (chunkLen == 0)
                    {
                        //if (http_data->fnChunkReplyCallback != NULL)
                        //{
                            //http_data->fnChunkReplyCallback((HTTP_HANDLE)data, http_data->userCtx, NULL, 0, http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, true);
                            //http_data->recvMsg.recvState = state_message_body;
                            //break;
                        //}
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
                            //if (http_data->fnChunkReplyCallback != NULL)
                            //{
                            //    http_data->fnChunkReplyCallback((HTTP_CLIENT_HANDLE)data, http_data->userCtx, BUFFER_u_char(http_data->recvMsg.msgBody), BUFFER_length(http_data->recvMsg.msgBody), http_data->recvMsg.statusCode, http_data->recvMsg.respHeader, false);
                            //}
                            //index += chunkLen+2;
                            //if (chunkLen != http_data->recvMsg.storedLen-index)
                            //{
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
        }*/
        if ( (http_data->recvMsg.requestType == HTTPAPI_REQUEST_HEAD && http_data->recvMsg.recvState == state_response_header) || 
            (http_data->recvMsg.recvState == state_message_body) || 
            (http_data->recvMsg.recvState == state_error) )
        {
            HTTPHeaders_Free(http_data->recvMsg.respHeader);
            http_data->recvMsg.respHeader = NULL;
            BUFFER_delete(http_data->recvMsg.msgBody);
            http_data->recvMsg.msgBody = NULL;
            free(http_data->recvMsg.storedBytes);
            http_data->recvMsg.storedBytes = NULL;
            http_data->recvMsg.storedLen = 0;
            http_data->recvMsg.recvState = state_complete;
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
            get_log_time(timeResult, TIME_MAX_BUFFER);
            LOG(LOG_TRACE, 0, "-> %s ", timeResult);
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
            get_log_time(timeResult, TIME_MAX_BUFFER);
            LOG(LOG_TRACE, 0, "-> %s ", timeResult);
            LOG(LOG_TRACE, 0, "%s", writeText);
        }
    }
    return result;
}

static char* create_request_line(HTTPAPI_REQUEST_TYPE requestType, const char* hostname, int port, const char* relativePath)
{
    char* result;

    // Get the Method to be used
    /* Codes_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
    const char* method = (requestType == HTTPAPI_REQUEST_HEAD) ? "HEAD"
        : (requestType == HTTPAPI_REQUEST_POST) ? "POST"
        : (requestType == HTTPAPI_REQUEST_PUT) ? "PUT"
        : (requestType == HTTPAPI_REQUEST_DELETE) ? "DELETE"
        : (requestType == HTTPAPI_REQUEST_CONNECT) ? "CONNECT"
        : (requestType == HTTPAPI_REQUEST_OPTIONS) ? "OPTIONS"
        : (requestType == HTTPAPI_REQUEST_TRACE) ? "TRACE"
        : "GET";

    const char* http_prefix = NULL;
    size_t buffLen = 0;
    /* Codes_SRS_HTTPAPI_07_023: [If the HTTPAPI_REQUEST_CONNECT type is specified HTTPAPI_ExecuteRequestAsync shall send the authority form of the request target ie 'Host: server.com:80' (rfc7231 4.3.6).] */
    if (requestType == HTTPAPI_REQUEST_CONNECT || port != HTTP_DEFAULT_PORT)
    {
        buffLen = strlen(HTTP_REQUEST_LINE_AUTHORITY_FMT)+strlen(method)+strlen(relativePath)+strlen(hostname)+strlen(relativePath)+4;
    }
    else
    {
        buffLen = strlen(HTTP_REQUEST_LINE_FMT)+strlen(method)+strlen(relativePath)+strlen(relativePath)+strlen(hostname)+strlen(relativePath);
    }
    if (port == HTTP_SECURE_PORT)
    {
        buffLen += strlen(HTTP_PREFIX_SECURE);
        http_prefix = HTTP_PREFIX_SECURE;
    }
    else
    {
        buffLen += strlen(HTTP_PREFIX);
        http_prefix = HTTP_PREFIX;
    }

    result = malloc(buffLen+1);
    if (result == NULL)
    {
        LogError("Failure allocating Request data");
    }
    else
    {
        /* Codes_SRS_HTTPAPI_07_025: [HTTPAPI_ExecuteRequestAsync shall use authority form of the request target if the port value is not the default http port (port 80) (rfc7230 5.3.3).] */
        if (requestType == HTTPAPI_REQUEST_CONNECT || port != HTTP_DEFAULT_PORT)
        {
            /* Codes_SRS_HTTPAPI_07_024: [HTTPAPI_ExecuteRequestAsync shall use absolute-form when generating the request Target (rfc7230 5.3.2).] */
            if (snprintf(result, buffLen+1, HTTP_REQUEST_LINE_AUTHORITY_FMT, method, http_prefix, hostname, port, relativePath) <= 0)
            {
                LogError("Failure writing request buffer");
                free(result);
                result = NULL;
            }
        }
        else
        {
            if (snprintf(result, buffLen+1, HTTP_REQUEST_LINE_FMT, method, http_prefix, hostname, relativePath) <= 0)
            {
                LogError("Failure writing request buffer");
                free(result);
                result = NULL;
            }
        }
    }
    return result;
}

static HTTPAPI_RESULT construct_http_headers(HTTPAPI_REQUEST_TYPE requestType, HTTP_HEADERS_HANDLE httpHeaderHandle, size_t contentLen, STRING_HANDLE http_preamble, const char* hostname, int port, bool chunkData)
{
    HTTPAPI_RESULT result;
    size_t headerCnt = 0;
    if (httpHeaderHandle != NULL && HTTPHeaders_GetHeaderCount(httpHeaderHandle, &headerCnt) != HTTP_HEADERS_OK)
    {
        LogError("Failed retrieving http header count.");
        /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
        result = HTTPAPI_HTTP_HEADERS_FAILED;
    }
    else
    {
        result = HTTPAPI_OK;
        bool hostNameFound = false;
        bool contentLenFound = false;
        for (size_t index = 0; index < headerCnt && result == 0; index++)
        {
            char* header;
            if (HTTPHeaders_GetHeader(httpHeaderHandle, index, &header) != HTTP_HEADERS_OK)
            {
                /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                result = HTTPAPI_HTTP_HEADERS_FAILED;
                LogError("Failed in HTTPHeaders_GetHeader");
            }
            else
            {
                size_t dataLen = strlen(header)+2;
                char* sendData = malloc(dataLen+1);
                if (sendData == NULL)
                {
                    /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                    result = HTTPAPI_ALLOC_FAILED;
                    LogError("Failed in allocating header data");
                }
                else
                {
                    if (strstr(header, HTTP_CONTENT_LEN) != NULL)
                    {
                        contentLenFound = true;
                    }
                    else if (strstr(header, HTTP_HOST_HEADER) != NULL)
                    {
                        hostNameFound = true;
                    }

                    if (snprintf(sendData, dataLen+1, "%s\r\n", header) <= 0)
                    {
                        result = HTTPAPI_ERROR;
                        LogError("Failed in constructing header data");
                    }
                    else
                    {
                        if (STRING_concat(http_preamble, sendData) != 0)
                        {
                            /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                            result = HTTPAPI_HTTP_HEADERS_FAILED;
                            LogError("Failed in building header data");
                        }
                    }
                    free(sendData);
                }
                free(header);
            }
        }

        if (result == HTTPAPI_OK)
        {
            if (chunkData)
            {
                if (STRING_concat(http_preamble, HTTP_CHUNKED_ENCODING_HDR) != 0)
                {
                    /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                    result = HTTPAPI_HTTP_HEADERS_FAILED;
                    LogError("Failed building content len header data");
                }
            }
            else
            {
                /* Codes_SRS_HTTPAPI_07_012: [HTTPAPI_ExecuteRequestAsync shall add the Content-Length http header to the request if not supplied and the length of the content is > 0 or the requestType is a POST (rfc7230 3.3.2).] */
                /* Codes_SRS_HTTPAPI_07_011: [If the requestType parameter is of type POST and the Content-Length not supplied HTTPAPI_ExecuteRequestAsync shall add the Content-Length header (rfc7230 3.3.2).] */
                if (!contentLenFound && (contentLen > 0 || requestType == HTTPAPI_REQUEST_POST) )
                {
                    size_t fmtLen = strlen(HTTP_CONTENT_LEN)+strlen(HTTP_CRLF_VALUE)+10;
                    char* content = malloc(fmtLen+1);
                    if (content == NULL)
                    {
                        /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                        result = HTTPAPI_HTTP_HEADERS_FAILED;
                        LogError("Failed allocating content len header data");
                    }
                    else
                    {
                        if (sprintf(content, "%s: %d%s", HTTP_CONTENT_LEN, (int)contentLen, HTTP_CRLF_VALUE) <= 0)
                        {
                            /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                            result = HTTPAPI_HTTP_HEADERS_FAILED;
                            LogError("Failed constructing content len header data");
                        }
                        else
                        {
                            if (STRING_concat(http_preamble, content) != 0)
                            {
                                /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                                result = HTTPAPI_HTTP_HEADERS_FAILED;
                                LogError("Failed building content len header data");
                            }
                        }
                        free(content);
                    }
                }
            }

            /* Codes_SRS_HTTPAPI_07_014: [HTTPAPI_ExecuteRequestAsync shall add the Host http header to the request if not supplied (rfc7230 5.4).] */
            if (!hostNameFound)
            {
                if (requestType == HTTPAPI_REQUEST_CONNECT)
                {
                    size_t fmtLen = strlen(HTTP_HOST_HEADER)+strlen(HTTP_CRLF_VALUE)+strlen(hostname)+8;
                    char* content = malloc(fmtLen+1);
                    if (content == NULL)
                    {
                        /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                        result = HTTPAPI_HTTP_HEADERS_FAILED;
                        LogError("Failed allocating content len header data");
                    }
                    else
                    {
                        if (sprintf(content, "%s: %s:%d%s", HTTP_HOST_HEADER, hostname, port, HTTP_CRLF_VALUE) <= 0)
                        {
                            /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                            result = HTTPAPI_HTTP_HEADERS_FAILED;
                            LogError("Failed constructing content len header data");
                        }
                        else
                        {
                            if (STRING_concat(http_preamble, content) != 0)
                            {
                                /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                                result = HTTPAPI_HTTP_HEADERS_FAILED;
                                LogError("Failed building content len header data");
                            }
                        }
                        free(content);
                    }
                }
                else
                {
                    size_t fmtLen = strlen(HTTP_HOST_HEADER)+strlen(HTTP_CRLF_VALUE)+strlen(hostname)+2;
                    char* content = malloc(fmtLen+1);
                    if (content == NULL)
                    {
                        result = HTTPAPI_HTTP_HEADERS_FAILED;
                        LogError("Failed allocating content len header data");
                    }
                    else
                    {
                        if (sprintf(content, "%s: %s%s", HTTP_HOST_HEADER, hostname, HTTP_CRLF_VALUE) <= 0)
                        {
                            /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                            result = HTTPAPI_HTTP_HEADERS_FAILED;
                            LogError("Failed constructing content len header data");
                        }
                        else
                        {
                            if (STRING_concat(http_preamble, content) != 0)
                            {
                                /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                                result = HTTPAPI_HTTP_HEADERS_FAILED;
                                LogError("Failed building content len header data");
                            }
                        }
                        free(content);
                    }
                }
            }

            if (STRING_concat(http_preamble, "\r\n") != 0)
            {
                /* Codes_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
                result = HTTPAPI_HTTP_HEADERS_FAILED;
                LogError("Failed sending header finalization data");
            }
        }
    }
    return result;
}

static HTTPAPI_RESULT send_http_data(HTTP_HANDLE_DATA* http_data, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath,
    HTTP_HEADERS_HANDLE httpHeadersHandle, size_t contentLength, bool sendChunked)
{
    HTTPAPI_RESULT result;
    STRING_HANDLE http_preamble;

    char* request_line = create_request_line(requestType, http_data->hostname, http_data->http_port, relativePath);
    if (request_line == NULL)
    {
        /* Codes_SRS_HTTPAPI_07_026: [If an error is encountered during the request line construction HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_REQUEST_LINE_PROCESSING_ERROR.] */
        result = HTTPAPI_REQUEST_LINE_PROCESSING_ERROR;
    }
    else
    {
        http_preamble = STRING_construct(request_line);
        if (http_preamble == NULL)
        {
            /* Codes_SRS_HTTPAPI_07_027: [If any memory allocation are encountered HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_ALLOC_FAILED.] */
            LogError("Failure creating buffer object");
            result = HTTPAPI_ALLOC_FAILED;
        }
        else
        {
            result = construct_http_headers(requestType, httpHeadersHandle, contentLength, http_preamble, http_data->hostname, http_data->http_port, sendChunked);
            if (result == HTTPAPI_OK)
            {
                if (write_http_text(http_data, STRING_c_str(http_preamble)) != 0)
                {
                    /* Codes_SRS_HTTPAPI_07_028: [If sending data through the xio object fails HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_SEND_REQUEST_FAILED.] */
                    result = HTTPAPI_SEND_REQUEST_FAILED;
                    LogError("Failure writing request buffer");
                }
                else
                {
                    result = HTTPAPI_OK;
                }
            }
            STRING_delete(http_preamble);
        }
        free(request_line);
    }
    return result;
}

HTTP_HANDLE HTTPAPI_CreateConnection(XIO_HANDLE xio, const char* hostName, int port)
{
    HTTP_HANDLE_DATA* http_data = NULL;
    /* Codes_SRS_HTTPAPI_07_002: [If any argument is NULL, HTTPAPI_CreateConnection shall return a NULL handle.] */
    if (hostName == NULL || xio == NULL)
    {
        LogInfo("Failure: invalid parameter was NULL");
    }
    /* Codes_SRS_HTTPAPI_07_004: [If the hostName parameter is greater than 64 characters then HTTPAPI_CreateConnection shall return a NULL handle (rfc1035 2.3.1).] */
    else if (strlen(hostName) > MAX_HOSTNAME_LEN)
    {
        LogInfo("Failure: Host name length is too long");
    }
    else
    {
        /* Codes_SRS_HTTPAPI_07_003: [If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.] */
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
                /* Codes_SRS_HTTPAPI_07_003: [If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.] */
                LogError("Failure opening xio connection");
                free(http_data);
                http_data = NULL;
            }
            /* Codes_SRS_HTTPAPI_07_005: [HTTPAPI_CreateConnection shall open the transport channel specified in the io parameter.] */
            else if (xio_open(http_data->xio_handle, on_io_open_complete, http_data, on_bytes_recv, http_data, on_io_error, http_data) != 0)
            {
                /* Codes_SRS_HTTPAPI_07_003: [If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.] */
                LogError("Failure allocating hostname");
                free(http_data->hostname);
                free(http_data);
                http_data = NULL;
            }
            else
            {
                http_data->http_port = port;
                http_data->is_connected = 0;
                http_data->is_io_error = 0;
                http_data->received_bytes_count = 0;
                http_data->received_bytes = NULL;
                http_data->logTrace = false;
                memset(&http_data->recvMsg, 0, sizeof(HTTP_RECV_DATA) );
                http_data->recvMsg.recvState = state_complete;
                http_data->recvMsg.chunkedReply = false;

            }
        }
    }
    /* Codes_SRS_HTTPAPI_07_001: [HTTPAPI_CreateConnection shall return on success a non-NULL handle to the HTTP interface.]*/
    return (HTTP_HANDLE)http_data;
}

void HTTPAPI_CloseConnection(HTTP_HANDLE handle)
{
    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
    /* Codes_SRS_HTTPAPI_07_006: [If the handle parameter is NULL, HTTPAPI_CloseConnection shall do nothing.] */
    if (http_data != NULL)
    {
        /* Codes_SRS_HTTPAPI_07_008: [HTTPAPI_CloseConnection shall close the transport channel associated with this connection.] */
        if (http_data->xio_handle != NULL)
        {
            (void)xio_close(http_data->xio_handle, NULL, NULL);
        }
        /* Codes_SRS_HTTPAPI_07_007: [HTTPAPI_CloseConnection shall free all resources associated with the HTTP_HANDLE.] */
        if (http_data->hostname)
        {
            free(http_data->hostname);
        }
        free(http_data);
    }
}

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
    (void)responseHeadersHandle;
    (void)responseContent;

    // This shall call into the HTTPAPI_ExecuteRequestAsync function once the recieve code is complete
    HTTPAPI_RESULT result = HTTPAPI_ERROR;
    return result;
}

HTTPAPI_RESULT HTTPAPI_ExecuteRequestAsync(HTTP_HANDLE handle, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath, HTTP_HEADERS_HANDLE httpHeadersHandle,
    const unsigned char* content, size_t contentLength, ON_EXECUTE_COMPLETE on_execute_complete, void* callback_context)
{
    HTTPAPI_RESULT result;

    HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;

    /* Codes_SRS_HTTPAPI_07_009: [If the parameters handle or relativePath are NULL, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.] */
    /* Codes_SRS_HTTPAPI_07_010: [If the parameters content is not NULL and contentLength is 0 or content is NULL and contentLength is not 0, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.] */
    if (http_data == NULL || relativePath == NULL ||
        (content != NULL && contentLength == 0) || (content == NULL && contentLength != 0))
    {
        result = HTTPAPI_INVALID_ARG;
    }
    /* Codes_SRS_HTTPAPI_07_013: [If HTTPAPI_ExecuteRequestAsync is called before a previous call is complete, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_IN_PROGRESS.] */
    else if (http_data->recvMsg.recvState != state_complete && 
        http_data->recvMsg.recvState != state_error)
    {
        result = HTTPAPI_IN_PROGRESS;
    }
    else
    {
        http_data->recvMsg.recvState = state_initial;
        http_data->recvMsg.fn_execute_complete = on_execute_complete;
        http_data->recvMsg.execute_ctx = callback_context;
        http_data->recvMsg.requestType = requestType;
        result = send_http_data(http_data, requestType, relativePath, httpHeadersHandle, contentLength, false);
        if (result == HTTPAPI_OK)
        {
            if (content != NULL && contentLength != 0)
            {
                if (write_http_data(http_data, content, contentLength) != 0)
                {
                    /* Codes_SRS_HTTPAPI_07_028: [If sending data through the xio object fails HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_SEND_REQUEST_FAILED.] */
                    result = HTTPAPI_SEND_REQUEST_FAILED;
                    LogError("Failure writing content buffer");
                    http_data->recvMsg.recvState = state_error;
                }
                else
                {
                    result = HTTPAPI_OK;
                }
            }
        }
        else
        {
            http_data->recvMsg.recvState = state_error;
        }
    }
    return result;
}

void HTTPAPI_DoWork(HTTP_HANDLE handle)
{
    /* Codes_SRS_HTTPAPI_07_015: [If the handle parameter is NULL, HTTPAPI_DoWork shall do nothing.] */
    if (handle != NULL)
    {
        HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
        /* Codes_SRS_HTTPAPI_07_016: [HTTPAPI_DoWork shall call into the XIO_HANDLE do work to execute transport communications.] */
        xio_dowork(http_data->xio_handle);
    }
}

HTTPAPI_RESULT HTTPAPI_SetOption(HTTP_HANDLE handle, const char* optionName, const void* value)
{
    HTTPAPI_RESULT result;
    /* Codes_SRS_HTTPAPI_07_018: [If handle or optionName parameters are NULL then HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.] */
    if (handle == NULL || optionName == NULL)
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("invalid parameter (NULL) passed to HTTPAPI_SetOption");
    }
    else if (strcmp("logtrace", optionName) == 0)
    {
        /* Codes_SRS_HTTPAPI_07_031: [If a specified option received an unsuspected NULL value HTTPAPI_SetOption shall return HTTPAPI_INVALID_ARG.] */
        if (value == NULL)
        {
            result = HTTPAPI_INVALID_ARG;
        }
        else
        {
            HTTP_HANDLE_DATA* http_data = (HTTP_HANDLE_DATA*)handle;
            http_data->logTrace = *((bool*)value);
            result = HTTPAPI_OK;
        }
    }
    else
    {
        /* Codes_SRS_HTTPAPI_07_019: [If HTTPAPI_SetOption encounteres a optionName that is not recognized HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.] */
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
        /* Codes_SRS_HTTPAPI_07_021: [If any parameter is NULL then HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.] */
        result = HTTPAPI_INVALID_ARG;
        LogError("invalid argument(NULL) passed to HTTPAPI_CloneOption");
    }
    else if (strcmp("logtrace", optionName) == 0)
    {
        bool* tempLogTrace = malloc(sizeof(bool) );
        if (tempLogTrace == NULL)
        {
            /* Codes_SRS_HTTPAPI_07_032: [If any allocation error are encounted HTTPAPI_CloneOption shall return HTTPAPI_ALLOC_FAILED.] */
            result = HTTPAPI_ALLOC_FAILED;
            LogError("unable to allocate logtrace in HTTPAPI_CloneOption");
        }
        else
        {
            /* Codes_SRS_HTTPAPI_07_020: [HTTPAPI_CloneOption shall clone the specified optionName value into the savedValue parameter.] */
            *tempLogTrace = value;
            *savedValue = tempLogTrace;
            result = HTTPAPI_OK;
        }
    }
    else
    {
        /* Codes_SRS_HTTPAPI_07_033: [If a specified option recieved an unsuspected NULL value HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.] */
        result = HTTPAPI_INVALID_ARG;
        LogError("unknown option %s", optionName);
    }
    return result;
}

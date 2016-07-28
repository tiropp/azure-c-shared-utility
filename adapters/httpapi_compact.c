// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include "azure_c_shared_utility/httpapi.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/threadapi.h"
#include <string.h>
#include <limits.h>

#define MAX_HOSTNAME     64
#define TEMP_BUFFER_SIZE 1024


DEFINE_ENUM_STRINGS(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)

typedef enum SEND_ALL_RESULT_TAG
{
    SEND_ALL_RESULT_NOT_STARTED,
    SEND_ALL_RESULT_PENDING,
    SEND_ALL_RESULT_OK,
    SEND_ALL_RESULT_ERROR
} SEND_ALL_RESULT;

typedef struct HTTP_HANDLE_DATA_TAG
{
    char*           certificate;
    XIO_HANDLE      xio_handle;
    size_t          received_bytes_count;
    unsigned char*  received_bytes;
    SEND_ALL_RESULT send_all_result;
    unsigned int    is_io_error : 1;
    unsigned int    is_connected : 1;
} HTTP_HANDLE_DATA;

/*the following function does the same as sscanf(pos2, "%d", &sec)*/
/*this function only exists because some of platforms do not have sscanf. */
static int ParseStringToDecimal(const char *src, int* dst)
{
	int result;
    char* next;
    (*dst) = strtol(src, &next, 0);
    if ((src == next) || ((((*dst) == LONG_MAX) || ((*dst) == LONG_MIN)) && (errno != 0)))
    {
		result = EOF;
    }
	else
	{
		result = 1;
	}
    return result;
}

/*the following function does the same as sscanf(pos2, "%x", &sec)*/
/*this function only exists because some of platforms do not have sscanf. This is not a full implementation; it only works with well-defined x numbers. */
#define HEXA_DIGIT_VAL(c)         (((c>='0') && (c<='9')) ? (c-'0') : ((c>='a') && (c<='f')) ? (c-'a'+10) : ((c>='A') && (c<='F')) ? (c-'A'+10) : -1)
static int ParseStringToHexadecimal(const char *src, int* dst)
{
	int result;
	if (src == NULL)
	{
		result = EOF;
	}
	else if (HEXA_DIGIT_VAL(*src) == -1)
	{
		result = EOF;
	}
	else
	{
		int digitVal;
		(*dst) = 0;
		while ((digitVal = HEXA_DIGIT_VAL(*src)) != -1)
		{
			(*dst) *= 0x10;
			(*dst) += digitVal;
			src++;
		}
		result = 1;
	}
    return result;
}

/*the following function does the same as sscanf(buf, "HTTP/%*d.%*d %d %*[^\r\n]", &ret) */
/*this function only exists because some of platforms do not have sscanf. This is not a full implementation; it only works with well-defined HTTP response. */
static int  ParseHttpResponse(const char* src, int* dst)
{
	int result;
	static const char HTTPPrefix[] = "HTTP/";
	if ((src == NULL) || (dst == NULL))
	{
		result = EOF;
	}
	else
	{
		bool fail = false;
		const char* runPrefix = HTTPPrefix;

		while((*runPrefix) != '\0')
		{
			if ((*runPrefix) != (*src))
			{
				fail = true;
				break;
			}
			src++;
			runPrefix++;
		}

		if (!fail)
		{
			while ((*src) != '.')
			{
				if ((*src) == '\0')
				{
					fail = true;
				}
				src++;
			}
		}

		if (!fail)
		{
			while ((*src) != ' ')
			{
				if ((*src) == '\0')
				{
					fail = true;
				}
				src++;
			}
		}

		if (fail)
		{
			result = EOF;
		}
		else
		{
			result = ParseStringToDecimal(src, dst);
		}
	}

    return result;
}

HTTPAPI_RESULT HTTPAPI_Init(void)
{
	/*Codes_SRS_httpapi_compact_21_005: [ The HTTPAPI_Init must allocate all memory to control the http protocol. ]*/
	/*Codes_SRS_httpapi_compact_21_008: [ If there is not enough memory to control the http protocol, the HTTPAPI_Init must return HTTPAPI_ALLOC_FAILED. ]*/
	/**
	 * No memory is necessary. 
	 */

	/*Codes_SRS_httpapi_compact_21_006: [ The HTTPAPI_Init must initialize all artifact to control the http protocol. ]*/
	/*Codes_SRS_httpapi_compact_21_009: [ If there is a problem initializing any artifact, the HTTPAPI_Init must return HTTPAPI_INIT_FAILED. ]*/
	/**
	* No artifact is necessary.
	*/

	/*Codes_SRS_httpapi_compact_21_007: [ If HTTPAPI_Init get success allocating all the needed memory, it must return HTTPAPI_OK. ]*/
    return HTTPAPI_OK;
}

void HTTPAPI_Deinit(void)
{
	/*Codes_SRS_httpapi_compact_21_010: [ The HTTPAPI_Init must release all memory allocated by the httpapi_compact. ]*/
	/**
	* No memory was necessary.
	*/

	/*Codes_SRS_httpapi_compact_21_011: [ The HTTPAPI_Init must release all artifact to control the http protocol. ]*/
	/**
	* No artifact was necessary.
	*/
}

/*Codes_SRS_httpapi_compact_21_012: [ The HTTPAPI_CreateConnection must create an http connection to the host specified by the hostName parameter. ]*/
HTTP_HANDLE HTTPAPI_CreateConnection(const char* hostName)
{
    HTTP_HANDLE_DATA* handle;

	if (hostName == NULL)
	{
		/*Codes_SRS_httpapi_compact_21_015: [ If the hostName is NULL, the HTTPAPI_CreateConnection must return NULL as the handle. ]*/
		LogError("Invalid host name. Null hostName parameter.");
		handle = NULL;
	}
	else if (*hostName == '\0')
	{
		/*Codes_SRS_httpapi_compact_21_016: [ If the hostName is empty, the HTTPAPI_CreateConnection must return NULL as the handle. ]*/
		LogError("Invalid host name. Empty string.");
		handle = NULL;
	}
	else
	{
		handle = (HTTP_HANDLE_DATA*)malloc(sizeof(HTTP_HANDLE_DATA));
		/*Codes_SRS_httpapi_compact_21_014: [ If there is not enough memory to control the http connection, the HTTPAPI_CreateConnection must return NULL as the handle. ]*/
		if (handle == NULL)
		{
			LogError("There is no memory to control the http connection");
		}
		else
		{
			TLSIO_CONFIG tlsio_config = { hostName, 443 };
			handle->xio_handle = xio_create(platform_get_default_tlsio(), (void*)&tlsio_config);

			/*Codes_SRS_httpapi_compact_21_017: [ If the HTTPAPI_CreateConnection failed to create the connection, it must return NULL as the handle. ]*/
			if (handle->xio_handle == NULL)
			{
				LogError("Create connection failed");
				free(handle);
				handle = NULL;
			}
			else
			{
				handle->is_connected = 0;
				handle->is_io_error = 0;
				handle->received_bytes_count = 0;
				handle->received_bytes = NULL;
				handle->send_all_result = SEND_ALL_RESULT_NOT_STARTED;
				handle->certificate = NULL;
			}
		}
	}

	/*Codes_SRS_httpapi_compact_21_013: [ The HTTPAPI_CreateConnection must return the connection handle(HTTP_HANDLE). ]*/
	return (HTTP_HANDLE)handle;
}

void HTTPAPI_CloseConnection(HTTP_HANDLE handle)
{
    HTTP_HANDLE_DATA* h = (HTTP_HANDLE_DATA*)handle;

	/*Codes_SRS_httpapi_compact_21_021: [ If the connection handle is NULL, the HTTPAPI_CloseConnection must not do anything. ]*/
	if (h != NULL)
    {
		/*Codes_SRS_httpapi_compact_21_020: [ If there is no previous connection, the HTTPAPI_CloseConnection must not do anything. ]*/
		if (h->xio_handle != NULL)
        {
			/*Codes_SRS_httpapi_compact_21_018: [ The HTTPAPI_CloseConnection must close the connection previously created in HTTPAPI_CreateConnection. ]*/
			LogInfo("Close http connection.");
            xio_destroy(h->xio_handle);
        }

		/*Codes_SRS_httpapi_compact_21_019: [ If there is a certificate associated to this connection, the HTTPAPI_CloseConnection must free all allocated memory for the certificate. ]*/
		if (h->certificate)
        {
            free(h->certificate);
        }

        free(h);
    }
}

static void on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
	if (context != NULL)
	{
		HTTP_HANDLE_DATA* h = (HTTP_HANDLE_DATA*)context;
		if (open_result == IO_OPEN_OK)
		{
			h->is_connected = 1;
			h->is_io_error = 0;
		}
		else
		{
			h->is_io_error = 1;
		}
	}
}

#define TOLOWER(c) (((c>='A') && (c<='Z'))?c-'A'+'a':c)
static int my_strnicmp(const char* s1, const char* s2, size_t n)
{
    int result;

	if ((s1 == NULL) || (s2 == NULL))
	{
		result = -1;
	}
	else
	{
		result = 0;
		while (((n--) >= 0) && ((*s1) != '\0') && ((*s2) != '\0') && (result == 0))
		{
			/* compute the difference between the chars */
			result = TOLOWER(*s1) - TOLOWER(*s2);
			s1++;
			s2++;
		}
	}

    return result;
}

static int my_stricmp(const char* s1, const char* s2)
{
	int result;

	if ((s1 == NULL) || (s2 == NULL))
	{
		result = -1;
	}
	else
	{
		result = 0;

		while (((*s1) != '\0') && ((*s2) != '\0') && (result == 0))
		{
			/* compute the difference between the chars */
			result = TOLOWER(*s1) - TOLOWER(*s2);
			s1++;
			s2++;
		}
	}

    return result;
}

static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
	if (context != NULL)
	{
		HTTP_HANDLE_DATA* h = (HTTP_HANDLE_DATA*)context;

		/* Here we got some bytes so we'll buffer them so the receive functions can consumer it */
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
}

static void on_io_error(void* context)
{
	if (context != NULL)
	{
		HTTP_HANDLE_DATA* h = (HTTP_HANDLE_DATA*)context;
		h->is_io_error = 1;
		LogError("on_io_error: Error signalled by underlying IO");
	}
}

static int conn_receive(HTTP_HANDLE_DATA* http_instance, char* buffer, int count)
{
    int result;

	if ((http_instance == NULL) || (buffer == NULL) || (count < 0))
	{
		result = -1;
	}
	else
	{
		while (result < count)
		{
			xio_dowork(http_instance->xio_handle);

			/* if any error was detected while receiving then simply break and report it */
			if (http_instance->is_io_error != 0)
			{
				result = -1;
				break;
			}

			if (http_instance->received_bytes_count >= (size_t)count)
			{
				/* Consuming bytes from the receive buffer */
				(void)memcpy(buffer, http_instance->received_bytes, count);
				(void)memmove(http_instance->received_bytes, http_instance->received_bytes + count, http_instance->received_bytes_count - count);
				http_instance->received_bytes_count -= count;

				/* we're not reallocating at each consumption so that we don't trash due to byte by byte consumption */
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
	if (context != NULL)
	{
		/* If a send is complete we'll simply signal this by changing the send all state */
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
}

static int conn_send_all(HTTP_HANDLE_DATA* http_instance, const char* buffer, int count)
{
    int result;

	if ((http_instance == NULL) || (buffer == 0) || (count < 0))
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
            /* We have to loop in here until all bytes are sent or we encounter an error. */
            while (1)
            {
                /* If we got an error signalled from the underlying IO we simply report it up */
                if (http_instance->is_io_error)
                {
                    http_instance->send_all_result = SEND_ALL_RESULT_ERROR;
                    break;
                }

                if (http_instance->send_all_result != SEND_ALL_RESULT_PENDING)
                {
                    break;
                }

                xio_dowork(http_instance->xio_handle);

                /* We yield the CPU for a bit so others can do their work */
                ThreadAPI_Sleep(1);
            }

            /* The send_all_result indicates what is the status for the send operation.
               Not started - means nothing should happen since no send was started
               Pending - a send was started, but it is still being carried out 
               Ok - Send complete
               Error - error */
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
	int result;
    char* p = buf;
    char  c;

	if (conn_receive(http_instance, &c, 1) < 0)
	{
		result = -1;
	}
	else
	{
		result = 0;
		while (c != '\r') 
		{
			if ((p - buf + 1) >= (int)size)
			{
				result = -1;
				break;
			}
			
			*p++ = c;
			if (conn_receive(http_instance, &c, 1) < 0)
			{
				result = -1;
				break;
			}
		}

		if (result != -1)
		{
			*p = 0;
			if (conn_receive(http_instance, &c, 1) < 0 || c != '\n') // skip \n
			{
				result = -1;
			}
		}

		result = p - buf;
	}

	return result;
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
		{
			break;
		}

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
		{
			org = -1;
			break;
		}

        n -= size;
    }

	if (org >= 0)
	{
		if (readChunk(http_instance, (char*)buf, n) < 0)
		{
			org = -1;
		}
	}

    return org;
}

/*Codes_SRS_httpapi_compact_21_022: [ The HTTPAPI_ExecuteRequest must execute the http communtication with the provided host, sending a request and reciving the response. ]*/
/*Codes_SRS_httpapi_compact_21_023: [ If a Certificate was provided, the HTTPAPI_ExecuteRequest must set this option on the transport layer. ]*/
/*Codes_SRS_httpapi_compact_21_024: [ If the transport failed setting the Certificate, the HTTPAPI_ExecuteRequest must not send any request and return HTTPAPI_SET_OPTION_FAILED. ]*/
/*Codes_SRS_httpapi_compact_21_025: [ The HTTPAPI_ExecuteRequest must open the transport connection with the host to send the request. ]*/
/*Codes_SRS_httpapi_compact_21_026: [ If the open process failed, the HTTPAPI_ExecuteRequest must not send any request and return HTTPAPI_OPEN_REQUEST_FAILED. ]*/
/*Codes_SRS_httpapi_compact_21_027: [ If the open process succeed, the HTTPAPI_ExecuteRequest must send the request message to the host. ]*/
/*Codes_SRS_httpapi_compact_21_028: [ If the HTTPAPI_ExecuteRequest cannot create a buffer to send the request, it must not send any request and return HTTPAPI_STRING_PROCESSING_ERROR. ]*/
/*Codes_SRS_httpapi_compact_21_029: [ If the HTTPAPI_ExecuteRequest cannot send the request header, it must return HTTPAPI_HTTP_HEADERS_FAILED. ]*/
/*Codes_SRS_httpapi_compact_21_030: [ If the HTTPAPI_ExecuteRequest cannot send the buffer with the request, it must return HTTPAPI_SEND_REQUEST_FAILED. ]*/
/*Codes_SRS_httpapi_compact_21_031: [ At the end of the transmission, the HTTPAPI_ExecuteRequest must receive the response from the host. ]*/
/*Codes_SRS_httpapi_compact_21_032: [ After receive the response, the HTTPAPI_ExecuteRequest must close the transport connection with the host. ]*/
/*Codes_SRS_httpapi_compact_21_033: [ If the HTTPAPI_ExecuteRequest cannot read the message with the request result, it must return HTTPAPI_READ_DATA_FAILED. ]*/
/*Codes_SRS_httpapi_compact_21_034: [ If the whole process succeed, the HTTPAPI_ExecuteRequest must retur HTTPAPI_OK. ]*/
/*Codes_SRS_httpapi_compact_21_035: [ If there is no previous connection, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. ]*/
/*Codes_SRS_httpapi_compact_21_036: [ The HTTPAPI_ExecuteRequest must execute resquest for types `GET`, `POST`, `PUT`, `DELETE`, `PATCH`. ]*/
/*Codes_SRS_httpapi_compact_21_037: [ The request type must be provided in the parameter requestType. ]*/
/*Codes_SRS_httpapi_compact_21_038: [ If the request type is unknown, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. ]*/
/*Codes_SRS_httpapi_compact_21_039: [ The HTTPAPI_ExecuteRequest must execute the resquest for the path in relativePath parameter. ]*/
/*Codes_SRS_httpapi_compact_21_040: [ If the relativePath is NULL or invalid, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. ]*/
/*Codes_SRS_httpapi_compact_21_041: [ The requst must contain the http header provided in httpHeadersHandle parameter. ]*/
/*Codes_SRS_httpapi_compact_21_042: [ If the httpHeadersHandle is NULL or invalid, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. ]*/
/*Codes_SRS_httpapi_compact_21_043: [ The request can contain the a content message, provided in content parameter. ]*/
/*Codes_SRS_httpapi_compact_21_044: [ If the content is NULL, the HTTPAPI_ExecuteRequest must send the request without content. ]*/
/*Codes_SRS_httpapi_compact_21_045: [ If the content is not NULL, the number of bytes in the content must be provided in contentLength parameter. ]*/
/*Codes_SRS_httpapi_compact_21_046: [ If the contentLength is lower than one, the HTTPAPI_ExecuteRequest must send the request without content. ]*/
/*Codes_SRS_httpapi_compact_21_047: [ The HTTPAPI_ExecuteRequest must return the http status reported by the host in the received response. ]*/
/*Codes_SRS_httpapi_compact_21_048: [ The HTTPAPI_ExecuteRequest must report the status in the statusCode parameter. ]*/
/*Codes_SRS_httpapi_compact_21_049: [ If the statusCode is NULL, the HTTPAPI_ExecuteRequest must report not report any status. ]*/
/*Codes_SRS_httpapi_compact_21_050: [ If responseHeadersHandle is provide, the HTTPAPI_ExecuteRequest must prepare a Response Header usign the HTTPHeaders_AddHeaderNameValuePair. ]*/
/*Codes_SRS_httpapi_compact_21_051: [ If there is a content in the response, the HTTPAPI_ExecuteRequest must copy it in the responseContent buffer. ]*/
/*Codes_SRS_httpapi_compact_21_052: [ If the responseContent is NULL, the HTTPAPI_ExecuteRequest must ignore any content in the response. ]*/
/*Codes_SRS_httpapi_compact_21_053: [ If any memory allocation get fail, the HTTPAPI_ExecuteRequest must return HTTPAPI_ALLOC_FAILED. ]*/
static const char httpapiRequestString[5][7] = { "GET", "POST", "PUT", "DELETE", "PATCH" };

//Note: This function assumes that "Host:" and "Content-Length:" headers are setup
//      by the caller of HTTPAPI_ExecuteRequest() (which is true for httptransport.c).
HTTPAPI_RESULT HTTPAPI_ExecuteRequest(HTTP_HANDLE handle, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath,
    HTTP_HEADERS_HANDLE httpHeadersHandle, const unsigned char* content,
    size_t contentLength, unsigned int* statusCode,
    HTTP_HEADERS_HANDLE responseHeadersHandle, BUFFER_HANDLE responseContent)
{
    HTTPAPI_RESULT result = HTTPAPI_ERROR;
    size_t  headersCount;
    char    buf[TEMP_BUFFER_SIZE];
    int     ret;
    size_t  bodyLength = 0;
    bool    chunked = false;
    const unsigned char* receivedContent;

    if (handle == NULL ||
        relativePath == NULL ||
        httpHeadersHandle == NULL ||
        HTTPHeaders_GetHeaderCount(httpHeadersHandle, &headersCount) != HTTP_HEADERS_OK)
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
        goto exit;
    }

    HTTP_HANDLE_DATA* httpHandle = (HTTP_HANDLE_DATA*)handle;

    if (httpHandle->is_connected == 0)
    {
        // Load the certificate
        if ((httpHandle->certificate != NULL) &&
			(xio_setoption(httpHandle->xio_handle, "TrustedCerts", httpHandle->certificate) != 0))
        {
            result = HTTPAPI_SET_OPTION_FAILED;
            LogError("Could not load certificate (result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }

        // Make the connection
        if (xio_open(httpHandle->xio_handle, on_io_open_complete, httpHandle , on_bytes_received, httpHandle, on_io_error, httpHandle) != 0)
        {
            result = HTTPAPI_OPEN_REQUEST_FAILED;
            LogError("Could not connect (result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
            goto exit;
        }

        while ((httpHandle->is_connected == 0) &&
			(httpHandle->is_io_error == 0))
        {
            xio_dowork(httpHandle->xio_handle);

			LogInfo("Waiting for TLS connection");

            ThreadAPI_Sleep(1);
        }
	}

	if (httpHandle->is_io_error != 0)
	{
		result = HTTPAPI_OPEN_REQUEST_FAILED;
		LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
		goto exit;
	}

    //Send request
    if ((ret = snprintf(buf, sizeof(buf), "%s %s HTTP/1.1\r\n", httpapiRequestString[requestType], relativePath)) < 0
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
    if (ParseHttpResponse(buf, &ret) != 1)
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

    while (*buf)
    {
        const char* ContentLength = "content-length:";
        const int ContentLengthSize = 16;
        const char* TransferEncoding = "transfer-encoding:";
        const int TransferEncodingSize = 19;

        if (my_strnicmp(buf, ContentLength, ContentLengthSize) == 0)
        {
            char* p = buf + ContentLengthSize;
            if (ParseStringToDecimal(p, &bodyLength) != 1)
            {
                result = HTTPAPI_READ_DATA_FAILED;
                LogError("(result = %s)", ENUM_TO_STRING(HTTPAPI_RESULT, result));
                goto exit;
            }
        }
        else if (my_strnicmp(buf, TransferEncoding, TransferEncodingSize) == 0)
        {
            const char* p = buf + TransferEncodingSize;
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
            if (ParseStringToHexadecimal(buf, &chunkSize) != 1)     // chunkSize is length of next line (/r/n is not counted)
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
        (httpHandle->is_io_error != 0))
    {
        xio_close(httpHandle->xio_handle, NULL, NULL);
        httpHandle->is_connected = 0;
    }

    return result;
}

HTTPAPI_RESULT HTTPAPI_SetOption(HTTP_HANDLE handle, const char* optionName, const void* value)
{
    HTTPAPI_RESULT result;
    if (
        (handle == NULL) ||
        (optionName == NULL) ||
        (value == NULL)
        )
    {
        result = HTTPAPI_INVALID_ARG;
        LogError("invalid parameter (NULL) passed to HTTPAPI_SetOption");
    }
    else if (strcmp("TrustedCerts", optionName) == 0)
    {
        HTTP_HANDLE_DATA* h = (HTTP_HANDLE_DATA*)handle;
        if (h->certificate)
        {
            free(h->certificate);
        }

        int len = strlen((char*)value);
        h->certificate = (char*)malloc(len + 1);
        if (h->certificate == NULL)
        {
            result = HTTPAPI_ERROR;
            LogError("unable to allocate certificate memory in HTTPAPI_SetOption");
        }
        else
        {
            (void)strcpy(h->certificate, (const char*)value);
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

HTTPAPI_RESULT HTTPAPI_CloneOption(const char* optionName, const void* value, const void** savedValue)
{
    HTTPAPI_RESULT result;
    if (
        (optionName == NULL) ||
        (value == NULL) ||
        (savedValue == NULL)
        )
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
            result = HTTPAPI_INVALID_ARG;
            LogError("unable to allocate certificate memory in HTTPAPI_CloneOption");
        }
        else
        {
            (void)strcpy(tempCert, (const char*)value);
            *savedValue = tempCert;
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

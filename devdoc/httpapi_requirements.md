HTTPAPI Requirements
================
 
## Overview

HTTAPI module provides a platform Independent http implementation

## Reference RFCs

- Http: https://tools.ietf.org/html/rfc7230.pdf
- Hostname: https://tools.ietf.org/html/rfc1035.pdf
- 100 Continue: https://tools.ietf.org/pdf/rfc7231.pdf
- Proxy: https://tools.ietf.org/html/rfc7235.pdf

## RFC features to be implemented soon

- (rfc7230) 6.3 Persistent Connections
- (rfc7231) 6.2.1 100 Continue Response
- (rfc7235) 3.2 Proxy Authentication

## Exposed API

```c
typedef struct HTTP_HANDLE_DATA_TAG* HTTP_HANDLE;

#define HTTPAPI_RESULT_VALUES                \
HTTPAPI_OK,                                  \
HTTPAPI_INVALID_ARG,                         \
HTTPAPI_ERROR,                               \
HTTPAPI_SET_OPTION_FAILED,                   \
HTTPAPI_IN_PROGRESS,                         \
HTTPAPI_SET_X509_FAILURE,                    \
HTTPAPI_SET_TIMEOUTS_FAILED,                 \
HTTPAPI_SEND_REQUEST_FAILED,                 \
HTTPAPI_ALLOC_FAILED,                        \
HTTPAPI_STRING_PROCESSING_ERROR,             \
HTTPAPI_HTTP_HEADERS_FAILED,                 \

DEFINE_ENUM(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES);

#define HTTPAPI_REQUEST_TYPE_VALUES \
    HTTPAPI_REQUEST_GET,            \
    HTTPAPI_REQUEST_HEAD,           \
    HTTPAPI_REQUEST_POST,           \
    HTTPAPI_REQUEST_PUT,            \
    HTTPAPI_REQUEST_DELETE,         \
    HTTPAPI_REQUEST_CONNECT,        \
    HTTPAPI_REQUEST_OPTIONS,        \
    HTTPAPI_REQUEST_TRACE           \

DEFINE_ENUM(HTTPAPI_REQUEST_TYPE, HTTPAPI_REQUEST_TYPE_VALUES);

typedef void(*ON_EXECUTE_COMPLETE)(void* callback_context, HTTPAPI_RESULT execute_result, unsigned int statusCode, HTTP_HEADERS_HANDLE respHeader, CONSTBUFFER_HANDLE responseBuffer);

MOCKABLE_FUNCTION(, HTTP_HANDLE, HTTPAPI_CreateConnection, XIO_HANDLE, xio, const char*, hostName);

MOCKABLE_FUNCTION(, void, HTTPAPI_CloseConnection, HTTP_HANDLE, handle);

MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_ExecuteRequestAsync, HTTP_HANDLE, handle, HTTPAPI_REQUEST_TYPE, requestType, const char*, relativePath,
    HTTP_HEADERS_HANDLE, httpHeadersHandle, const unsigned char*, content,
    size_t, contentLength, ON_EXECUTE_COMPLETE, on_send_complete, void*, callback_context);

MOCKABLE_FUNCTION(, void, HTTPAPI_DoWork, HTTP_HANDLE, handle);
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_SetOption, HTTP_HANDLE, handle, const char*, optionName, const void*, value);
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_CloneOption, const char*, optionName, const void*, value, const void**, savedValue);
```

### HTTPAPI_CreateConnection

```c
HTTP_HANDLE HTTPAPI_CreateConnection(XIO_HANDLE xio, const char* hostName)
```

**SRS_HTTPAPI_07_001: [**HTTPAPI_CreateConnection shall return on success a non-NULL handle to the HTTP interface.**]**  
**SRS_HTTPAPI_07_002: [**If any argument is NULL, HTTPAPI_CreateConnection shall return a NULL handle.**]**  
**SRS_HTTPAPI_07_003: [**If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.**]**  
**SRS_HTTPAPI_07_004: [**If the hostName parameter is greater than 64 characters then, HTTPAPI_CreateConnection shall return a NULL handle (rfc1035 2.3.1).**]**  
**SRS_HTTPAPI_07_005: [**HTTPAPI_CreateConnection shall open the transport channel specified in the io parameter.**]**  

### HTTPAPI_CloseConnection

```c
void HTTPAPI_CloseConnection(HTTP_HANDLE handle)
```

**SRS_HTTPAPI_07_006: [**If the handle parameter is NULL, HTTPAPI_CloseConnection shall do nothing.**]**  
**SRS_HTTPAPI_07_007: [**HTTPAPI_CloseConnection shall free all resources associated with the HTTP_HANDLE.**]**  
**SRS_HTTPAPI_07_008: [**HTTPAPI_CloseConnection shall close the transport channel associated with this connection.**]**  

### HTTPAPI_ExecuteRequestAsync

```c
HTTPAPI_RESULT HTTPAPI_ExecuteRequestAsync(HTTP_HANDLE handle, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath, HTTP_HEADERS_HANDLE httpHeadersHandle,
    const unsigned char* content, size_t contentLength, ON_EXECUTE_COMPLETE on_send_complete, void* callback_context)
```

**SRS_HTTPAPI_07_009: [**If the parameters handle or relativePath are NULL, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.**]**  
**SRS_HTTPAPI_07_010: [**If the parameters content is not NULL and contentLength is 0 or content is NULL and contentLength is not 0, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.**]**  
**SRS_HTTPAPI_07_011: [**If the requestType is not a valid request HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.**]**
**SRS_HTTPAPI_07_022: [**HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).**]**  
**SRS_HTTPAPI_07_012: [**HTTPAPI_ExecuteRequestAsync shall add the Content-Length http header to the request if not supplied and the length of the content is > 0 or the requestType is a POST (rfc7230 3.3.2).**]**  
**SRS_HTTPAPI_07_013: [**If HTTPAPI_ExecuteRequestAsync is called before a previous call is complete, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_IN_PROGRESS.**]**  
**SRS_HTTPAPI_07_014: [**HTTPAPI_ExecuteRequestAsync shall add the HOST http header to the request if not supplied (rfc7230 5.4).**]**  

### HTTPAPI_DoWork

```c
void HTTPAPI_DoWork(HTTP_HANDLE handle)
```

**SRS_HTTPAPI_07_015: [**If the handle parameter is NULL, HTTPAPI_DoWork shall do nothing.**]**  
**SRS_HTTPAPI_07_016: [**HTTPAPI_DoWork shall call into the XIO_HANDLE do work to execute transport communications.**]**  

### HTTPAPI_SetOption

```c
HTTPAPI_RESULT HTTPAPI_SetOption(HTTP_HANDLE handle, const char* optionName, const void* value)
```

**SRS_HTTPAPI_07_017: [**If HTTPAPI_SetOption successfully sets the given option with the supplied value it shall return HTTPAPI_OK.**]**  
**SRS_HTTPAPI_07_018: [**If handle or optionName parameters are NULL then HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.**]**  
**SRS_HTTPAPI_07_019: [**If HTTPAPI_SetOption encounteres a optionName that is not recognized HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.**]**  

<table>
<tr><th>Parameter</th><th>Possible Values</th><th>Details</th></tr>
<tr><td>TrustedCerts</td><td></td><td>Sets the certificate to be used by the transport.</td></tr>
<tr><td>logtrace</td><td>true or false</td><td>Turn on or off logging of the transport data. Default: false.</td></tr>
<tr><td>x509certificate</td><td></td><td>Sets the x509 certificate to be used by the transport.</td></tr>
<tr><td>x509privatekey</td><td></td><td>Sets the x509 private Key to be used by the transport.</td></tr>
<tr><td>proxyAddress</td><td></td><td>Sets the proxy address used by the transport.</td></tr>
<tr><td>proxyUsername</td><td></td><td>Sets the proxy user used by the transport.</td></tr>
<tr><td>proxyPassword</td><td></td><td>Sets the proxy password used by the transport.</td></tr>
<table>  

### HTTPAPI_CloneOption

```c
HTTPAPI_RESULT HTTPAPI_CloneOption(const char* optionName, const void* value, const void** savedValue)
```

**SRS_HTTPAPI_07_020: [**HTTPAPI_CloneOption shall clone the specified optionName value into the savedValue parameter.**]**  
**SRS_HTTPAPI_07_021: [**If any parameter is NULL then HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.**]**  
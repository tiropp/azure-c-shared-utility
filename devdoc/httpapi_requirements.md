HTTPAPI Requirements
================
 
##Overview
HTTAPI module provides a platform Independent http implementation

## Reference RFC
https://tools.ietf.org/html/rfc7230

## RFC 7230 features not yet supported
8.1.0 Persistent Connections
8.2.3 100 Continue Response 
14.33 Proxy Authentication

##Exposed API
```c
typedef struct HTTP_HANDLE_DATA_TAG* HTTP_HANDLE;

typedef void(*ON_EXECUTE_COMPLETE)(void* callback_context, unsigned int statusCode, HTTP_HEADERS_HANDLE responseHeadersHandle, BUFFER_HANDLE responseContent);

#define HTTPAPI_RESULT_VALUES                \
HTTPAPI_OK,                                  \
HTTPAPI_INVALID_ARG,                         \
HTTPAPI_ERROR,                               \
HTTPAPI_OPEN_REQUEST_FAILED,                 \
HTTPAPI_SET_OPTION_FAILED,                   \
HTTPAPI_ALREADY_INIT,                        \
HTTPAPI_SET_X509_FAILURE,                    \
HTTPAPI_SET_TIMEOUTS_FAILED,                 \
HTTPAPI_SEND_REQUEST_FAILED,                 \

DEFINE_ENUM(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES);

#define HTTPAPI_REQUEST_TYPE_VALUES \
    HTTPAPI_REQUEST_OPTIONS,        \
    HTTPAPI_REQUEST_GET,            \
    HTTPAPI_REQUEST_POST,           \
    HTTPAPI_REQUEST_PUT,            \
    HTTPAPI_REQUEST_DELETE,         \
    HTTPAPI_REQUEST_PATCH           \

DEFINE_ENUM(HTTPAPI_REQUEST_TYPE, HTTPAPI_REQUEST_TYPE_VALUES);

MOCKABLE_FUNCTION(, HTTP_HANDLE, HTTPAPI_CreateConnection, const char*, hostName);

MOCKABLE_FUNCTION(, void, HTTPAPI_CloseConnection, HTTP_HANDLE, handle);

MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_ExecuteRequestAsync, HTTP_HANDLE, handle, HTTPAPI_REQUEST_TYPE, requestType, const char*, relativePath,
    HTTP_HEADERS_HANDLE, httpHeadersHandle, const unsigned char*, content,
    size_t, contentLength, ON_EXECUTE_COMPLETE, on_send_complete, void*, callback_context);

MOCKABLE_FUNCTION(, void, HTTPAPI_DoWork, HTTP_HANDLE, handle);
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_SetOption, HTTP_HANDLE, handle, const char*, optionName, const void*, value);
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_CloneOption, const char*, optionName, const void*, value, const void**, savedValue);
```

###HTTPAPI_CreateConnection
```c
HTTP_HANDLE HTTPAPI_CreateConnection(XIO_HANDLE io, const char* hostName)
```
**SRS_XIO_01_001: [**HTTPAPI_CreateConnection shall return on successful a non-NULL handle to the HTTP interface.**]**
If any argument is NULL, HTTPAPI_CreateConnection shall return a NULL handle.
If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.
If the hostName parameter is greater than 255 then, HTTPAPI_CreateConnection shall return a NULL handle. 

###HTTPAPI_CloseConnection
```c
void HTTPAPI_CloseConnection(HTTP_HANDLE handle)
```
If the handle parameter is NULL, HTTPAPI_CloseConnection shall do nothing.
HTTPAPI_CloseConnection shall free all resources associated with the HTTP_HANDLE.

###HTTPAPI_ExecuteRequestAsync
```c
HTTPAPI_RESULT HTTPAPI_ExecuteRequestAsync(HTTP_HANDLE handle, HTTPAPI_REQUEST_TYPE requestType, const char* relativePath, HTTP_HEADERS_HANDLE httpHeadersHandle,
    const unsigned char* content, size_t contentLength, ON_EXECUTE_COMPLETE on_send_complete, void* callback_context)
```
If the parameters handle or relativePath are NULL, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.
If the parameters content is not NULL and contentLength is NULL or content is NULL and contentLength is not NULL, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.
If the requestType is not a valid request HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_ERROR
HTTPAPI_ExecuteRequestAsync shall add the Content-Length http header item to the request if the contentLength is > 0 (rfc 3.3.2)
If HTTPAPI_ExecuteRequestAsync is called before a previous call is incomplete, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_ALREADY_INIT 
HTTPAPI_ExecuteRequestAsync shall add the HOST http header item to the request if not supplied (rfc - 5.4).

###HTTPAPI_DoWork
```c
void HTTPAPI_DoWork(HTTP_HANDLE handle)
```
If the handle parameter is NULL, HTTPAPI_DoWork shall do nothing.

###HTTPAPI_SetOption
```c
HTTPAPI_RESULT HTTPAPI_SetOption(HTTP_HANDLE handle, const char* optionName, const void* value)
```

###HTTPAPI_CloneOption
```c
HTTPAPI_RESULT HTTPAPI_CloneOption(const char* optionName, const void* value, const void** savedValue)
```

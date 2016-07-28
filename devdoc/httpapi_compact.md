httpapi_compact
=============

## Overview

httpapi_compact implements a compact version of the HTTP (Hypertext Transfer Protocol).  

## References

[http://](http://httpwg.org/)

##Exposed API

**SRS_httpapi_compact_21_001: [** The httpapi_compact must implement the methods defined by the `httpapi.h`. **]**
**SRS_httpapi_compact_21_002: [** The httpapi_compact must support the http requests:
```c
#define HTTPAPI_REQUEST_TYPE_VALUES \
    HTTPAPI_REQUEST_GET,            \
    HTTPAPI_REQUEST_POST,           \
    HTTPAPI_REQUEST_PUT,            \
    HTTPAPI_REQUEST_DELETE,         \
    HTTPAPI_REQUEST_PATCH           \

/** @brief Enumeration specifying the HTTP request verbs accepted by
 *	the HTTPAPI module.
 */
DEFINE_ENUM(HTTPAPI_REQUEST_TYPE, HTTPAPI_REQUEST_TYPE_VALUES);
```
**]**

**SRS_httpapi_compact_21_003: [** The httpapi_compact must support the httpapi methods:
```c
/**
 * @brief	Global initialization for the HTTP API component.
 *
 *			Platform specific implementations are expected to initialize
 *			the underlying HTTP API stacks.
 * 
 * @return	@c HTTPAPI_OK if initialization is successful or an error
 * 			code in case it fails.
 */
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_Init);

/** @brief	Free resources allocated in ::HTTPAPI_Init. */
MOCKABLE_FUNCTION(, void, HTTPAPI_Deinit);

/**
 * @brief	Creates an HTTPS connection to the host specified by the @p
 * 			hostName parameter.
 *
 * @param	hostName	Name of the host.
 *
 *			This function returns a handle to the newly created connection.
 *			You can use the handle in subsequent calls to execute specific
 *			HTTP calls using ::HTTPAPI_ExecuteRequest.
 * 
 * @return	A @c HTTP_HANDLE to the newly created connection or @c NULL in
 * 			case an error occurs.
 */
MOCKABLE_FUNCTION(, HTTP_HANDLE, HTTPAPI_CreateConnection, const char*, hostName);

/**
 * @brief	Closes a connection created with ::HTTPAPI_CreateConnection.
 *
 * @param	handle	The handle to the HTTP connection created via ::HTTPAPI_CreateConnection.
 * 					
 * 			All resources allocated by ::HTTPAPI_CreateConnection should be
 * 			freed in ::HTTPAPI_CloseConnection.
 */
MOCKABLE_FUNCTION(, void, HTTPAPI_CloseConnection, HTTP_HANDLE, handle);

/**
 * @brief	Sends the HTTP request to the host and handles the response for
 * 			the HTTP call.
 *
 * @param	handle				 	The handle to the HTTP connection created
 * 									via ::HTTPAPI_CreateConnection.
 * @param	requestType			 	Specifies which HTTP method is used (GET,
 * 									POST, DELETE, PUT, PATCH).
 * @param	relativePath		 	Specifies the relative path of the URL
 * 									excluding the host name.
 * @param	httpHeadersHandle	 	Specifies a set of HTTP headers (name-value
 * 									pairs) to be added to the
 * 									HTTP request. The @p httpHeadersHandle
 * 									handle can be created and setup with
 * 									the proper name-value pairs by using the
 * 									HTTPHeaders APIs available in @c
 * 									HTTPHeaders.h.
 * @param	content				 	Specifies a pointer to the request body.
 * 									This value is optional and can be @c NULL.
 * @param	contentLength		 	Specifies the request body size (this is
 * 									typically added into the HTTP headers as
 * 									the Content-Length header). This value is
 * 									optional and can be 0.
 * @param   statusCode   	        This is an out parameter, where
 * 									::HTTPAPI_ExecuteRequest returns the status
 * 									code from the HTTP response (200, 201, 400,
 * 									401, etc.)
 * @param	responseHeadersHandle	This is an HTTP headers handle to which
 * 									::HTTPAPI_ExecuteRequest must add all the
 * 									HTTP response headers so that the caller of
 * 									::HTTPAPI_ExecuteRequest can inspect them.
 * 									You can manipulate @p responseHeadersHandle
 * 									by using the HTTPHeaders APIs available in
 * 									@c HTTPHeaders.h
 * @param	responseContent		 	This is a buffer that must be filled by
 * 									::HTTPAPI_ExecuteRequest with the contents
 * 									of the HTTP response body. The buffer size
 * 									must be increased by the
 * 									::HTTPAPI_ExecuteRequest implementation in
 * 									order to fit the response body.
 * 									::HTTPAPI_ExecuteRequest must also handle
 * 									chunked transfer encoding for HTTP responses.
 * 									To manipulate the @p responseContent buffer,
 * 									use the APIs available in @c Strings.h.
 *
 * @return	@c HTTPAPI_OK if the API call is successful or an error
 * 			code in case it fails.
 */
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_ExecuteRequest, HTTP_HANDLE, handle, HTTPAPI_REQUEST_TYPE, requestType, const char*, relativePath,
                                             HTTP_HEADERS_HANDLE, httpHeadersHandle, const unsigned char*, content,
                                             size_t, contentLength, unsigned int*, statusCode,
                                             HTTP_HEADERS_HANDLE, responseHeadersHandle, BUFFER_HANDLE, responseContent);

/**
 * @brief	Sets the option named @p optionName bearing the value
 * 			@p value for the HTTP_HANDLE @p handle.
 *
 * @param	handle	  	The handle to the HTTP connection created via
 * 						::HTTPAPI_CreateConnection.
 * @param	optionName	A @c NULL terminated string representing the name
 * 						of the option.
 * @param	value	  	A pointer to the value for the option.
 *
 * @return	@c HTTPAPI_OK if initialization is successful or an error
 * 			code in case it fails.
 */
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_SetOption, HTTP_HANDLE, handle, const char*, optionName, const void*, value);

/**
 * @brief	Clones the option named @p optionName bearing the value @p value
 * 			into the pointer @p savedValue.
 *
 * @param	optionName	A @c NULL terminated string representing the name of
 * 						the option
 * @param	value	  	A pointer to the value of the option.
 * @param	savedValue	This pointer receives the copy of the value of the
 * 						option. The copy needs to be free-able.
 *
 * @return	@c HTTPAPI_OK if initialization is successful or an error
 * 			code in case it fails.
 */
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_CloneOption, const char*, optionName, const void*, value, const void**, savedValue);
```
**]**

**SRS_httpapi_compact_21_004: [** The httpapi_compact must return error code defined by HTTPAPI_RESULT:
```c
#define HTTPAPI_RESULT_VALUES                \
HTTPAPI_OK,                                  \
HTTPAPI_INVALID_ARG,                         \
HTTPAPI_ERROR,                               \
HTTPAPI_OPEN_REQUEST_FAILED,                 \
HTTPAPI_SET_OPTION_FAILED,                   \
HTTPAPI_SEND_REQUEST_FAILED,                 \
HTTPAPI_RECEIVE_RESPONSE_FAILED,             \
HTTPAPI_QUERY_HEADERS_FAILED,                \
HTTPAPI_QUERY_DATA_AVAILABLE_FAILED,         \
HTTPAPI_READ_DATA_FAILED,                    \
HTTPAPI_ALREADY_INIT,                        \
HTTPAPI_NOT_INIT,                            \
HTTPAPI_HTTP_HEADERS_FAILED,                 \
HTTPAPI_STRING_PROCESSING_ERROR,             \
HTTPAPI_ALLOC_FAILED,                        \
HTTPAPI_INIT_FAILED,                         \
HTTPAPI_INSUFFICIENT_RESPONSE_BUFFER,        \
HTTPAPI_SET_X509_FAILURE,                    \
HTTPAPI_SET_TIMEOUTS_FAILED                  \

/** @brief Enumeration specifying the possible return values for the APIs in  
 *		   this module.
 */
DEFINE_ENUM(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES);
```
**]**

###HTTPAPI_Init
```c
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_Init);
```
**SRS_httpapi_compact_21_005: [** The HTTPAPI_Init must allocate all memory to control the http protocol. **]**
**SRS_httpapi_compact_21_006: [** The HTTPAPI_Init must initialize all artifact to control the http protocol. **]**
**SRS_httpapi_compact_21_007: [** If HTTPAPI_Init get success allocating all the needed memory, it must return HTTPAPI_OK. **]**
**SRS_httpapi_compact_21_008: [** If there is not enough memory to control the http protocol, the HTTPAPI_Init must return HTTPAPI_ALLOC_FAILED. **]**
**SRS_httpapi_compact_21_009: [** If there is a problem initializing any artifact, the HTTPAPI_Init must return HTTPAPI_INIT_FAILED. **]**

###HTTPAPI_Deinit
```c
MOCKABLE_FUNCTION(, void, HTTPAPI_Deinit);
```
**SRS_httpapi_compact_21_010: [** The HTTPAPI_Init must release all memory allocated by the httpapi_compact. **]**
**SRS_httpapi_compact_21_011: [** The HTTPAPI_Init must release all artifact to control the http protocol. **]**

###HTTPAPI_CreateConnection
```c
MOCKABLE_FUNCTION(, HTTP_HANDLE, HTTPAPI_CreateConnection, const char*, hostName);
```
**SRS_httpapi_compact_21_012: [** The HTTPAPI_CreateConnection must create an http connection to the host specified by the hostName parameter. **]**
**SRS_httpapi_compact_21_013: [** The HTTPAPI_CreateConnection must return the connection handle (HTTP_HANDLE). **]**
**SRS_httpapi_compact_21_014: [** If there is not enough memory to control the http connection, the HTTPAPI_CreateConnection must return NULL as the handle. **]**
**SRS_httpapi_compact_21_015: [** If the hostName is NULL, the HTTPAPI_CreateConnection must return NULL as the handle. **]**
**SRS_httpapi_compact_21_016: [** If the hostName is empty, the HTTPAPI_CreateConnection must return NULL as the handle. **]**
**SRS_httpapi_compact_21_017: [** If the HTTPAPI_CreateConnection failed to create the connection, it must return NULL as the handle. **]**

###HTTPAPI_CloseConnection
```c
MOCKABLE_FUNCTION(, void, HTTPAPI_CloseConnection, HTTP_HANDLE, handle);
```
**SRS_httpapi_compact_21_018: [** The HTTPAPI_CloseConnection must close the connection previously created in HTTPAPI_CreateConnection. **]**
**SRS_httpapi_compact_21_019: [** If there is a certificate associated to this connection, the HTTPAPI_CloseConnection must free all allocated memory for the certificate. **]**
**SRS_httpapi_compact_21_020: [** If there is no previous connection, the HTTPAPI_CloseConnection must not do anything. **]**
**SRS_httpapi_compact_21_021: [** If the connection handle is NULL, the HTTPAPI_CloseConnection must not do anything. **]**

###HTTPAPI_ExecuteRequest
```c
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_ExecuteRequest, HTTP_HANDLE, handle, HTTPAPI_REQUEST_TYPE, requestType, const char*, relativePath,
                                             HTTP_HEADERS_HANDLE, httpHeadersHandle, const unsigned char*, content,
                                             size_t, contentLength, unsigned int*, statusCode,
                                             HTTP_HEADERS_HANDLE, responseHeadersHandle, BUFFER_HANDLE, responseContent);
```
**SRS_httpapi_compact_21_022: [** The HTTPAPI_ExecuteRequest must execute the http communtication with the provided host, sending a request and reciving the response. **]**
**SRS_httpapi_compact_21_023: [** If a Certificate was provided, the HTTPAPI_ExecuteRequest must set this option on the transport layer. **]**
**SRS_httpapi_compact_21_024: [** If the transport failed setting the Certificate, the HTTPAPI_ExecuteRequest must not send any request and return HTTPAPI_SET_OPTION_FAILED. **]**
**SRS_httpapi_compact_21_025: [** The HTTPAPI_ExecuteRequest must open the transport connection with the host to send the request. **]**
**SRS_httpapi_compact_21_026: [** If the open process failed, the HTTPAPI_ExecuteRequest must not send any request and return HTTPAPI_OPEN_REQUEST_FAILED. **]**
**SRS_httpapi_compact_21_027: [** If the open process succeed, the HTTPAPI_ExecuteRequest must send the request message to the host. **]**
**SRS_httpapi_compact_21_028: [** If the HTTPAPI_ExecuteRequest cannot create a buffer to send the request, it must not send any request and return HTTPAPI_STRING_PROCESSING_ERROR. **]**
**SRS_httpapi_compact_21_029: [** If the HTTPAPI_ExecuteRequest cannot send the request header, it must return HTTPAPI_HTTP_HEADERS_FAILED. **]**
**SRS_httpapi_compact_21_030: [** If the HTTPAPI_ExecuteRequest cannot send the buffer with the request, it must return HTTPAPI_SEND_REQUEST_FAILED. **]**
**SRS_httpapi_compact_21_031: [** At the end of the transmission, the HTTPAPI_ExecuteRequest must receive the response from the host. **]**
**SRS_httpapi_compact_21_032: [** After receive the response, the HTTPAPI_ExecuteRequest must close the transport connection with the host. **]**
**SRS_httpapi_compact_21_033: [** If the HTTPAPI_ExecuteRequest cannot read the message with the request result, it must return HTTPAPI_READ_DATA_FAILED. **]**
**SRS_httpapi_compact_21_034: [** If the whole process succeed, the HTTPAPI_ExecuteRequest must retur HTTPAPI_OK. **]**
**SRS_httpapi_compact_21_035: [** If there is no previous connection, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. **]**
**SRS_httpapi_compact_21_036: [** The HTTPAPI_ExecuteRequest must execute resquest for types `GET`, `POST`, `PUT`, `DELETE`, `PATCH`. **]**
**SRS_httpapi_compact_21_037: [** The request type must be provided in the parameter requestType. **]**
**SRS_httpapi_compact_21_038: [** If the request type is unknown, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. **]**
**SRS_httpapi_compact_21_039: [** The HTTPAPI_ExecuteRequest must execute the resquest for the path in relativePath parameter. **]**
**SRS_httpapi_compact_21_040: [** If the relativePath is NULL or invalid, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. **]**
**SRS_httpapi_compact_21_041: [** The requst must contain the http header provided in httpHeadersHandle parameter. **]**
**SRS_httpapi_compact_21_042: [** If the httpHeadersHandle is NULL or invalid, the HTTPAPI_ExecuteRequest must return HTTPAPI_INVALID_ARG. **]**
**SRS_httpapi_compact_21_043: [** The request can contain the a content message, provided in content parameter. **]**
**SRS_httpapi_compact_21_044: [** If the content is NULL, the HTTPAPI_ExecuteRequest must send the request without content. **]**
**SRS_httpapi_compact_21_045: [** If the content is not NULL, the number of bytes in the content must be provided in contentLength parameter. **]**
**SRS_httpapi_compact_21_046: [** If the contentLength is lower than one, the HTTPAPI_ExecuteRequest must send the request without content. **]**
**SRS_httpapi_compact_21_047: [** The HTTPAPI_ExecuteRequest must return the http status reported by the host in the received response. **]**
**SRS_httpapi_compact_21_048: [** The HTTPAPI_ExecuteRequest must report the status in the statusCode parameter. **]**
**SRS_httpapi_compact_21_049: [** If the statusCode is NULL, the HTTPAPI_ExecuteRequest must report not report any status. **]**
**SRS_httpapi_compact_21_050: [** If responseHeadersHandle is provide, the HTTPAPI_ExecuteRequest must prepare a Response Header usign the HTTPHeaders_AddHeaderNameValuePair. **]**
**SRS_httpapi_compact_21_051: [** If there is a content in the response, the HTTPAPI_ExecuteRequest must copy it in the responseContent buffer. **]**
**SRS_httpapi_compact_21_052: [** If the responseContent is NULL, the HTTPAPI_ExecuteRequest must ignore any content in the response. **]**
**SRS_httpapi_compact_21_053: [** If any memory allocation get fail, the HTTPAPI_ExecuteRequest must return HTTPAPI_ALLOC_FAILED. **]**

###HTTPAPI_SetOption
```c
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_SetOption, HTTP_HANDLE, handle, const char*, optionName, const void*, value);
```




###HTTPAPI_CloneOption
```c
MOCKABLE_FUNCTION(, HTTPAPI_RESULT, HTTPAPI_CloneOption, const char*, optionName, const void*, value, const void**, savedValue);
```

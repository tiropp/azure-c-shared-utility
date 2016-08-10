// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stddef.h>

static const char* TEST_HOSTNAME = "www.hostname.com";

static void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

static void my_gballoc_free(void* ptr)
{
    free(ptr);
}

#include "testrunnerswitcher.h"
#include "umock_c.h"

#include "umocktypes_bool.h"
#include "umocktypes_stdint.h"
#include "umock_c_negative_tests.h"

#define ENABLE_MOCKS

#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/constbuffer.h"

#undef ENABLE_MOCKS

/*#ifdef __cplusplus
extern "C"
{
#endif

    int STRING_sprintf(STRING_HANDLE handle, const char* format, ...);

#ifdef __cplusplus
}
#endif*/

static BUFFER_HANDLE my_BUFFER_new(void)
{
    return (BUFFER_HANDLE)my_gballoc_malloc(1);
}

static void my_BUFFER_delete(BUFFER_HANDLE handle)
{
    my_gballoc_free(handle);
}

static STRING_HANDLE my_STRING_construct(const char* psz)
{
    (void)psz;
    return (STRING_HANDLE)my_gballoc_malloc(1);
}

static void my_STRING_delete(STRING_HANDLE handle)
{
    my_gballoc_free(handle);
}

#include "azure_c_shared_utility/httpapi.h"

TEST_DEFINE_ENUM_TYPE(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)
IMPLEMENT_UMOCK_C_ENUM_TYPE(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES);

static const XIO_HANDLE TEST_IO_HANDLE = (XIO_HANDLE)0x11;
static const unsigned char* TEST_BUFFER_U_CHAR = (const unsigned char*)0x12;
static size_t TEST_BUFFER_SIZE = 12;
static const CONSTBUFFER_HANDLE TEST_CONSTBUFFER_VALUE = (CONSTBUFFER_HANDLE)0x13;
static const HTTP_HEADERS_HANDLE TEST_HEADER_HANDLE = (HTTP_HEADERS_HANDLE)0x14;

//g_on_bytes_recv
static ON_IO_OPEN_COMPLETE g_openComplete;
static ON_BYTES_RECEIVED g_on_bytes_recv;
static ON_IO_ERROR g_ioError;
static ON_SEND_COMPLETE g_on_send_complete;
static void* g_onCompleteCtx;
static void* g_onSendCtx;
static void* g_on_bytes_recv_ctx;
static void* g_ioErrorCtx;

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;

static bool g_execute_complete_called = false;

static size_t g_header_count = 0;
static HTTP_HEADERS_RESULT g_header_result = HTTP_HEADERS_OK;
static HTTP_HEADERS_RESULT g_hdr_result = HTTP_HEADERS_OK;

static const size_t TEXT_CONTENT_LENGTH = 70;

static const char* TEST_STRING_VALUE = "Test string value";
static const char* TEST_RELATIVE_PATH = "/";
static const unsigned char* TEST_HTTP_CONTENT = (const unsigned char*)"grant_type=client_credentials&client_id=d14d2b5&client_secret=shhhhhh";
static const char* OPTION_LOG_TRACE = "logtrace";
static const char* INVALID_OPTION_LOG_TRACE = "invalid_option";

static const char* TEST_HTTP_GET_BUFFER = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n \
Vary: Authorization, Accept\r\nAccept-Ranges: bytes\r\nContent-Length: 58\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n<html>\r\n<body>\r\n<h1>Hello, World!</h1>\r\n</body>\r\n</html>\r\n";
static const char* TEST_HTTP_HEAD_BUFFER = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n \
Vary: Authorization, Accept\r\nAccept-Ranges: bytes\r\nContent-Length: 88\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n";
static const char* TEST_HTTP_POST_BUFFER = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n \
ETag: \"34aa387-d-1568eb00\"\r\nVary: Authorization,Accept\r\nAccept-Ranges: bytes\r\nContent-Length: 73\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n\r\n<html>\r\n<body>\r\n<h1>Request Processed Successfully</h1>\r\n</body>\r\n</html>";
static const char* TEST_HTTP_PUT_BUFFER = "HTTP/1.1 201 Created\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nContent-type: text/html\r\nContent-length: 56\r\nConnection: Closed\r\n\r\n<html><body><h1>The file was created.</h1></body></html>";
static const char* TEST_HTTP_DELETE_BUFFER = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nContent-type: text/html\r\nContent-length: 30\r\nConnection: Closed\r\n\r\n<html><body><h1>URL deleted.</h1></body></html>";
static const char* TEST_HTTP_CONNECT_BUFFER = "HTTP/1.1 200 Connection established\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)";
static const char* TEST_HTTP_OPTIONS_BUFFER = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nAllow: GET, HEAD, POST, OPTIONS, TRACE\r\nContent-Type: httpd/unix-directory";
static const char* TEST_HTTP_TRACE_BUFFER = "";

static HTTP_HEADERS_HANDLE my_HTTPHeaders_Alloc(void)
{
    return (HTTP_HEADERS_HANDLE)my_gballoc_malloc(1);
}

static void my_HTTPHeaders_Free(HTTP_HEADERS_HANDLE h)
{
    my_gballoc_free(h);
}

static HTTP_HEADERS_RESULT my_HTTPHeaders_GetHeader(HTTP_HEADERS_HANDLE handle, size_t index, char** destination)
{
    (void)handle;
    if (g_hdr_result == HTTP_HEADERS_OK)
    {
        const char* header_value;
        switch (index)
        {
            case 0:
                header_value = "Authorization: SharedAccessSignature sr=iot-sdks-test.azure-devices.net&sig=etg5&se=14";
                break;
            case 1:
                header_value = "Accept: application/json";
                break;
            case 2:
                header_value = "Host: iot-sdks-test.azure-devices.net";
                break;
            case 3:
            default:
                header_value = "Content-Length: 123";
                break;
        }
        size_t len = strlen(header_value);
        *destination = (char*)my_gballoc_malloc(len+1);
        if (*destination != NULL)
        {
            strcpy(*destination, header_value);
            g_hdr_result = HTTP_HEADERS_OK;
        }
        else
        {
            g_hdr_result = HTTP_HEADERS_ERROR;
        }
    }
    return g_hdr_result;
}

static HTTP_HEADERS_RESULT my_HTTPHeaders_GetHeaderCount(HTTP_HEADERS_HANDLE handle, size_t* headerCount)
{
    (void)handle;
    *headerCount = g_header_count;
    return g_header_result;
}

static int my_xio_open(XIO_HANDLE handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    (void)handle;
    g_openComplete = on_io_open_complete;
    g_onCompleteCtx = on_io_open_complete_context;
    g_on_bytes_recv = on_bytes_received;
    g_on_bytes_recv_ctx = on_bytes_received_context;
    g_ioError = on_io_error;
    g_ioErrorCtx = on_io_error_context;
    return 0;
}

static int my_xio_send(XIO_HANDLE xio, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    (void)xio;
    (void)buffer;
    (void)size;
    g_on_send_complete = on_send_complete;
    g_onSendCtx = callback_context;
    return 0;
}

static int my_mallocAndStrcpy_s(char** destination, const char* source)
{
    (void)source;
    size_t l = strlen(source);
    *destination = (char*)my_gballoc_malloc(l + 1);
    strcpy(*destination, source);
    return 0;
}

/*#ifdef __cplusplus
extern "C"
{
#endif
int STRING_sprintf(STRING_HANDLE handle, const char* format, ...)
{
    (void)handle;
    (void)format;
    return 0;
}
#ifdef __cplusplus
}
#endif*/

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    (void)error_code;
    ASSERT_FAIL("umock_c reported error");
}

//MOCK_STATIC_METHOD_3(, int, STRING_sprintf, STRING_HANDLE, handle, const char*, format, ...)
//MOCK_METHOD_END(int, 0);

BEGIN_TEST_SUITE(httpapi_unittests)

TEST_SUITE_INITIALIZE(suite_init)
{
    int result;

    TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);
    result = umocktypes_bool_register_types();
    ASSERT_ARE_EQUAL(int, 0, result);

    result = umocktypes_stdint_register_types();
    ASSERT_ARE_EQUAL(int, 0, result);

    REGISTER_UMOCK_ALIAS_TYPE(XIO_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_SEND_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(BUFFER_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_OPEN_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_BYTES_RECEIVED, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_ERROR, void*);
    REGISTER_UMOCK_ALIAS_TYPE(CONSTBUFFER_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(CONSTBUFFER_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(STRING_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(HTTP_HEADERS_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_CLOSE_COMPLETE, void*);
    
    //REGISTER_GLOBAL_MOCK_HOOK(STRING_sprintf, my_STRING_sprintf);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_Alloc, my_HTTPHeaders_Alloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(HTTPHeaders_Alloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_Free, my_HTTPHeaders_Free);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_AddHeaderNameValuePair, HTTP_HEADERS_OK);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(HTTPHeaders_AddHeaderNameValuePair, HTTP_HEADERS_ERROR);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_ReplaceHeaderNameValuePair, HTTP_HEADERS_OK);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(HTTPHeaders_ReplaceHeaderNameValuePair, HTTP_HEADERS_ERROR);

    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_GetHeader, my_HTTPHeaders_GetHeader);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(HTTPHeaders_GetHeader, HTTP_HEADERS_ERROR);
    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_GetHeaderCount, my_HTTPHeaders_GetHeaderCount);

    REGISTER_GLOBAL_MOCK_HOOK(BUFFER_new, my_BUFFER_new);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(BUFFER_new, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(BUFFER_delete, my_BUFFER_delete);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_u_char, (unsigned char*)TEST_BUFFER_U_CHAR);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_length, TEST_BUFFER_SIZE);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_build, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(BUFFER_build, __LINE__);

    REGISTER_GLOBAL_MOCK_HOOK(xio_open, my_xio_open);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_open, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(xio_send, my_xio_send);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_send, __LINE__);
    REGISTER_GLOBAL_MOCK_RETURN(xio_close, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_close, __LINE__);

    REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, my_mallocAndStrcpy_s);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mallocAndStrcpy_s, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(STRING_construct, my_STRING_construct);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(STRING_construct, NULL);

    REGISTER_GLOBAL_MOCK_HOOK(STRING_delete, my_STRING_delete);
    REGISTER_GLOBAL_MOCK_RETURN(STRING_c_str, TEST_STRING_VALUE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(STRING_c_str, TEST_STRING_VALUE);
    REGISTER_GLOBAL_MOCK_RETURN(STRING_concat, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(STRING_concat, __LINE__);

    REGISTER_GLOBAL_MOCK_RETURN(CONSTBUFFER_CreateFromBuffer, TEST_CONSTBUFFER_VALUE);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
    TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    TEST_MUTEX_ACQUIRE(test_serialize_mutex);

    g_openComplete = NULL;
    g_onCompleteCtx = NULL;
    g_on_send_complete = NULL;
    g_onSendCtx = NULL;
    g_on_bytes_recv = NULL;
    g_ioError = NULL;
    g_on_bytes_recv_ctx = NULL;
    g_ioErrorCtx = NULL;
    g_header_count = 0;
    g_header_result = HTTP_HEADERS_OK;
    g_hdr_result = HTTP_HEADERS_OK;
    g_execute_complete_called = false;
    umock_c_reset_all_calls();
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    
    TEST_MUTEX_RELEASE(test_serialize_mutex);
}

static int should_skip_index(size_t current_index, const size_t skip_array[], size_t length)
{
    int result = 0;
    for (size_t index = 0; index < length; index++)
    {
        if (current_index == skip_array[index])
        {
            result = __LINE__;
            break;
        }
    }
    return result;
}

static void setup_httpapi_createconnection_mocks()
{
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_NUM_ARG, TEST_HOSTNAME))
        .IgnoreArgument(1);
    STRICT_EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5)
        .IgnoreArgument(6)
        .IgnoreArgument(7);
}

static void setup_httpapi_executerequestasync_mocks()
{
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);
    EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void setup_httpapi_executerequestasync_with_header_mocks(size_t header_count, bool content_len_included, bool include_content)
{
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG)).IgnoreArgument(2);

    for (size_t index = 0; index < header_count; index++)
    {
        EXPECTED_CALL(HTTPHeaders_GetHeader(TEST_HEADER_HANDLE, 0, IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    if (content_len_included)
    {
        EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_c_str(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);
    EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    if (include_content)
    {
        STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
            .IgnoreArgument(2)
            .IgnoreArgument(3)
            .IgnoreArgument(4)
            .IgnoreArgument(5);
    }
}

static void setup_httpapi_on_bytes_recv_mocks(size_t header_count, bool has_content)
{
    STRICT_EXPECTED_CALL(HTTPHeaders_Alloc());
    STRICT_EXPECTED_CALL(BUFFER_new());
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    for (size_t index = 0; index < header_count; index++)
    {
        EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        EXPECTED_CALL(HTTPHeaders_AddHeaderNameValuePair(IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    if (has_content)
    {
        EXPECTED_CALL(BUFFER_build(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
        EXPECTED_CALL(CONSTBUFFER_CreateFromBuffer(IGNORED_PTR_ARG));
        EXPECTED_CALL(CONSTBUFFER_Destroy(IGNORED_PTR_ARG));
    }
    EXPECTED_CALL(HTTPHeaders_Free(IGNORED_PTR_ARG));
    EXPECTED_CALL(BUFFER_delete(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void my_on_execute_complete(void* callback_context, HTTPAPI_RESULT execute_result, unsigned int statusCode, HTTP_HEADERS_HANDLE respHeader, CONSTBUFFER_HANDLE responseBuffer)
{
    (void)callback_context;
    (void)execute_result;
    (void)statusCode;
    (void)respHeader;
    (void)responseBuffer;
    g_execute_complete_called = true;
}

/* Tests_SRS_HTTPAPI_07_002: [If any argument is NULL, HTTPAPI_CreateConnection shall return a NULL handle.] */
TEST_FUNCTION(httpapi_createconnection_hostname_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle;

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, NULL, DEFAULT_HTTP_SECURE_PORT);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_002: [If any argument is NULL, HTTPAPI_CreateConnection shall return a NULL handle.] */
TEST_FUNCTION(httpapi_createconnection_XIO_HANDLE_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle;

    //act
    handle = HTTPAPI_CreateConnection(NULL, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_004: [If the hostName parameter is greater than 64 characters then HTTPAPI_CreateConnection shall return a NULL handle (rfc1035 2.3.1).] */
TEST_FUNCTION(httpapi_createconnection_hostname_too_long_fail)
{
    //arrange
    HTTP_HANDLE handle;

    // Construct an invalid hostname
    char invalid_hostname[72];
    size_t count = sizeof(invalid_hostname);
    for (size_t index = 0; index < count; index++)
    {
        invalid_hostname[index] = (char)(0x41+index);
    }
    invalid_hostname[count-1] = 0x00;

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, invalid_hostname, DEFAULT_HTTP_SECURE_PORT);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_001: [HTTPAPI_CreateConnection shall return on success a non-NULL handle to the HTTP interface.]*/
/* Tests_SRS_HTTPAPI_07_005: [HTTPAPI_CreateConnection shall open the transport channel specified in the io parameter.] */
TEST_FUNCTION(httpapi_createconnection_succeed)
{
    //arrange
    setup_httpapi_createconnection_mocks();

    //act
    HTTP_HANDLE http_handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);

    //assert
    ASSERT_IS_NOT_NULL(http_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(http_handle);
}

/* Tests_SRS_HTTPAPI_07_003: [If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.] */
/* Tests_SRS_HTTPAPI_07_003: [If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.] */
/* Tests_SRS_HTTPAPI_07_003: [If any failure is encountered, HTTPAPI_CreateConnection shall return a NULL handle.] */
TEST_FUNCTION(httpapi_createconnection_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    setup_httpapi_createconnection_mocks();

    umock_c_negative_tests_snapshot();

    //act
    for (size_t index = 0; index < umock_c_negative_tests_call_count(); index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_createconnection failure in test %zu", index);
        HTTP_HANDLE http_handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
        ASSERT_IS_NULL_WITH_MSG(http_handle, tmp_msg);
    }

    // Cleanup
    umock_c_negative_tests_deinit();
}

/* Tests_SRS_HTTPAPI_07_006: [If the handle parameter is NULL, HTTPAPI_CloseConnection shall do nothing.] */
TEST_FUNCTION(httpapi_closeconnection_handle_null_succeed)
{
    //arrange

    //act
    HTTPAPI_CloseConnection(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_008: [HTTPAPI_CloseConnection shall close the transport channel associated with this connection.] */
/* Tests_SRS_HTTPAPI_07_007: [HTTPAPI_CloseConnection shall free all resources associated with the HTTP_HANDLE.] */
TEST_FUNCTION(httpapi_closeconnection_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).IgnoreArgument(2).IgnoreArgument(2);
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    HTTPAPI_CloseConnection(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_009: [If the parameters handle or relativePath are NULL, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_executerequestasync_HANDLE_NULL_fail)
{
    //arrange

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(NULL, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_009: [If the parameters handle or relativePath are NULL, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_executerequestasync_relativePath_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, NULL, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_010: [If the parameters content is NULL and contentLength is not 0, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_executerequestasync_content_NULL_contentLength_valid_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_013: [If HTTPAPI_ExecuteRequestAsync is called before a previous call is complete, HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_IN_PROGRESS.] */
TEST_FUNCTION(httpapi_executerequestasync_invalid_state_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

   //act
    http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_IN_PROGRESS, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
/* Tests_SRS_HTTPAPI_07_014: [HTTPAPI_ExecuteRequestAsync shall add the HOST http header to the request if not supplied (rfc7230 5.4).] */
TEST_FUNCTION(httpapi_executerequestasync_GET_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_026: [If an error is encountered during the request line construction HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_REQUEST_LINE_PROCESSING_ERROR.] */
/* Tests_SRS_HTTPAPI_07_027: [If any memory allocation are encountered HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_ALLOC_FAILED.] */
/* Tests_SRS_HTTPAPI_07_028: [If sending data through the xio object fails HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_SEND_REQUEST_FAILED.] */
TEST_FUNCTION(httpapi_executerequestasync_GET_failures)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 4, 6, 8, 9 };

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0]) ) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_executerequestasync_GET failure in test %zu", index);

        HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

        //assert
        ASSERT_ARE_NOT_EQUAL_WITH_MSG(HTTPAPI_RESULT, HTTPAPI_OK, http_result, tmp_msg);
    }

    // Cleanup
    umock_c_negative_tests_deinit();
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_011: [If the requestType parameter is of type POST and the Content-Length not supplied HTTPAPI_ExecuteRequestAsync shall add the Content-Length header (rfc7230 3.3.2).] */
TEST_FUNCTION(httpapi_executerequestasync_GET_content_len_request_included_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    g_header_count = 4;
    setup_httpapi_executerequestasync_with_header_mocks(g_header_count, false, false);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_014: [HTTPAPI_ExecuteRequestAsync shall add the host http header to the request if not supplied (rfc7230 5.4).] */
TEST_FUNCTION(httpapi_executerequestasync_GET_host_request_included_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    g_header_count = 3;
    setup_httpapi_executerequestasync_with_header_mocks(g_header_count, false, false);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
TEST_FUNCTION(httpapi_executerequestasync_GetHeader_return_ERROR_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));
    EXPECTED_CALL(HTTPHeaders_GetHeader(TEST_HEADER_HANDLE, 0, IGNORED_PTR_ARG));

    EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    g_header_count = 1;

    g_hdr_result = HTTP_HEADERS_ERROR;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_HTTP_HEADERS_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
TEST_FUNCTION(httpapi_executerequestasync_GetHeaderCount_return_0_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    STRICT_EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG))
        .IgnoreArgument(2);

    EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    g_header_result = HTTP_HEADERS_ERROR;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_HTTP_HEADERS_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
TEST_FUNCTION(httpapi_executerequestasync_HEAD_type_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, NULL, NULL, 0, NULL, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_HEAD_type_failures)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] ={ 4, 6, 8, 9 };

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_executerequestasync_HEAD failure in test %zu", index);

        //act
        HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, NULL, NULL, 0, NULL, NULL);

        //assert
        ASSERT_ARE_NOT_EQUAL_WITH_MSG(HTTPAPI_RESULT, HTTPAPI_OK, http_result, tmp_msg);
    }

    // Cleanup
    umock_c_negative_tests_deinit();
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
/* Tests_SRS_HTTPAPI_07_012: [HTTPAPI_ExecuteRequestAsync shall add the Content-Length http header to the request if not supplied and the length of the content is > 0 or the requestType is a POST (rfc7230 3.3.2).] */
/* Tests_SRS_HTTPAPI_07_011: [If the requestType parameter is of type POST and the Content-Length not supplied HTTPAPI_ExecuteRequestAsync shall add the Content-Length header (rfc7230 3.3.2).] */
TEST_FUNCTION(httpapi_executerequestasync_POST_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_PORT);
    umock_c_reset_all_calls();

    g_header_count = 1;
    setup_httpapi_executerequestasync_with_header_mocks(g_header_count, true, true);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_POST, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_028: [If sending data through the xio object fails HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_SEND_REQUEST_FAILED.] */
/* Tests_SRS_HTTPAPI_07_029: [If an error is encountered during the construction of the http headers HTTPAPI_ExecuteRequestAsync shall return HTTPAPI_HTTP_HEADERS_FAILED.] */
TEST_FUNCTION(httpapi_executerequestasync_POST_failure)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_PORT);
    umock_c_reset_all_calls();

    g_header_count = 1;
    setup_httpapi_executerequestasync_with_header_mocks(g_header_count, true, true);

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 2, 6, 7, 10, 13, 15, 17, 18 };

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_executerequestasync_POST failure in test %zu/%zu", index, count);

        HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_POST, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

        //assert
        ASSERT_ARE_NOT_EQUAL_WITH_MSG(HTTPAPI_RESULT, HTTPAPI_OK, http_result, tmp_msg);
    }

    // Cleanup
    umock_c_negative_tests_deinit();
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_012: [HTTPAPI_ExecuteRequestAsync shall add the Content-Length http header to the request if not supplied and the length of the content is > 0 or the requestType is a POST (rfc7230 3.3.2).] */
/* Tests_SRS_HTTPAPI_07_025: [HTTPAPI_ExecuteRequestAsync shall use authority form of the request target if the port value is not the default http port (port 80) (rfc7230 5.3.3).] */
TEST_FUNCTION(httpapi_executerequestasync_DELETE_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 8080);
    umock_c_reset_all_calls();

    g_header_count = 0;
    setup_httpapi_executerequestasync_with_header_mocks(g_header_count, true, true);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_DELETE, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
/* Tests_SRS_HTTPAPI_07_012: [HTTPAPI_ExecuteRequestAsync shall add the Content-Length http header to the request if not supplied and the length of the content is > 0 or the requestType is a POST (rfc7230 3.3.2).] */
TEST_FUNCTION(httpapi_executerequestasync_PUT_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 80);
    umock_c_reset_all_calls();

    g_header_count = 3;
    setup_httpapi_executerequestasync_with_header_mocks(g_header_count, true, true);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_PUT, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
/* Tests_SRS_HTTPAPI_07_023: [If the HTTPAPI_REQUEST_CONNECT type is specified HTTPAPI_ExecuteRequestAsync shall send the authority form of the request target ie 'Host: server.com:80' (rfc7231 4.3.6).] */
/* Tests_SRS_HTTPAPI_07_024: [HTTPAPI_ExecuteRequestAsync shall use absolute-form when generating the request Target (rfc7230 5.3.2).] */
TEST_FUNCTION(httpapi_executerequestasync_CONNECT_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_CONNECT, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_CONNECT_failures)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 4, 6, 8, 9 };

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_executerequestasync_POST failure in test %zu/%zu", index, count);

        //act
        HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_CONNECT, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

        //assert
        ASSERT_ARE_NOT_EQUAL_WITH_MSG(HTTPAPI_RESULT, HTTPAPI_OK, http_result, tmp_msg);
    }

    // Cleanup
    umock_c_negative_tests_deinit();
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
TEST_FUNCTION(httpapi_executerequestasync_OPTIONS_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_OPTIONS, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_022: [HTTPAPI_ExecuteRequestAsync shall support all valid HTTP request types (rfc7231 4.3).] */
TEST_FUNCTION(httpapi_executerequestasync_TRACE_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    setup_httpapi_executerequestasync_mocks();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_TRACE, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_016: [HTTPAPI_DoWork shall call into the XIO_HANDLE do work to execute transport communications.] */
TEST_FUNCTION(httpapi_doWork_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(xio_dowork(TEST_IO_HANDLE));

    //act
    HTTPAPI_DoWork(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_015: [If the handle parameter is NULL, HTTPAPI_DoWork shall do nothing.] */
TEST_FUNCTION(httpapi_doWork_handle_NULL_fail)
{
    //arrange

    //act
    HTTPAPI_DoWork(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_018: [If handle or optionName parameters are NULL then HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.] */
TEST_FUNCTION(httpapi_setoption_handle_NULL_fail)
{
    //arrange

    //act
    bool logtrace = true;
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(NULL, OPTION_LOG_TRACE, (const void*)&logtrace);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_018: [If handle or optionName parameters are NULL then HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.] */
TEST_FUNCTION(httpapi_setoption_option_name_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    //act
    bool trace = false;
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, NULL, (const void*)&trace);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_019: [If HTTPAPI_SetOption encounteres a optionName that is not recognized HTTPAPI_SetOption shall return HTTP_CLIENT_INVALID_ARG.] */
TEST_FUNCTION(httpapi_setoption_unknown_option_name_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    //act
    bool trace = false;
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, INVALID_OPTION_LOG_TRACE, (const void*)&trace);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_031: [If a specified option received an unsuspected NULL value HTTPAPI_SetOption shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_setoption_log_trace_value_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_LOG_TRACE, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_017: [If HTTPAPI_SetOption successfully sets the given option with the supplied value it shall return HTTPAPI_OK.] */
TEST_FUNCTION(httpapi_setoption_log_trace_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    umock_c_reset_all_calls();

    //act
    bool trace = false;
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_LOG_TRACE, (const void*)&trace);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

/* Tests_SRS_HTTPAPI_07_021: [If any parameter is NULL then HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_cloneoption_optionName_NULL_fail)
{
    //arrange

    //act
    bool trace = false;
    bool* savedValue = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(NULL, &trace, (const void**)&savedValue);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_IS_NULL(savedValue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_021: [If any parameter is NULL then HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_cloneoption_value_NULL_fail)
{
    //arrange

    //act
    bool* savedValue = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_LOG_TRACE, NULL, (const void**)&savedValue);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_IS_NULL(savedValue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_021: [If any parameter is NULL then HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_cloneoption_savedvalue_NULL_fail)
{
    //arrange

    //act
    bool trace = false;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_LOG_TRACE, &trace, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

/* Tests_SRS_HTTPAPI_07_032: [If any allocation error are encounted HTTPAPI_CloneOption shall return HTTPAPI_ALLOC_FAILED.] */
TEST_FUNCTION(httpapi_cloneoption_logtrace_alloc_fail)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG))
        .IgnoreArgument_size()
        .SetReturn((void_ptr)NULL);

    //act
    bool logtrace = false;
    bool* savedValue = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_LOG_TRACE, &logtrace, (const void**)&savedValue);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_ALLOC_FAILED, http_result);
    ASSERT_IS_NULL(savedValue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    free(savedValue);
}

/* Tests_SRS_HTTPAPI_07_020: [HTTPAPI_CloneOption shall clone the specified optionName value into the savedValue parameter.] */
TEST_FUNCTION(httpapi_cloneoption_logtrace_succeed)
{
    //arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    //act
    bool logtrace = false;
    bool* savedValue;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_LOG_TRACE, &logtrace, (const void**)&savedValue);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_IS_NOT_NULL(savedValue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    free(savedValue);
}

/* Tests_SRS_HTTPAPI_07_033: [If a specified option recieved an unsuspected NULL value HTTPAPI_CloneOption shall return HTTPAPI_INVALID_ARG.] */
TEST_FUNCTION(httpapi_cloneoption_unknown_options_fail)
{
    //arrange

    //act
    bool logtrace = false;
    bool* savedValue = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(INVALID_OPTION_LOG_TRACE, &logtrace, (const void**)&savedValue);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_IS_NULL(savedValue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_on_bytes_recv_context_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    //act
    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    g_on_bytes_recv(NULL, (const unsigned char*)TEST_HTTP_GET_BUFFER, strlen(TEST_HTTP_GET_BUFFER) );

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_on_bytes_recv_buffer_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    //act
    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    g_on_bytes_recv(g_on_bytes_recv_ctx, NULL, strlen(TEST_HTTP_GET_BUFFER));

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_on_bytes_recv_len_0_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    //act
    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    g_on_bytes_recv(g_on_bytes_recv_ctx, (const unsigned char*)TEST_HTTP_HEAD_BUFFER, 0);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_on_bytes_recv_GET_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    size_t buffer_len = strlen(TEST_HTTP_GET_BUFFER);
    const unsigned char* buffer = (const unsigned char*)TEST_HTTP_GET_BUFFER;

    setup_httpapi_on_bytes_recv_mocks(8, true);

    //act
    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    g_on_bytes_recv(g_on_bytes_recv_ctx, buffer, buffer_len);

    //assert
    ASSERT_IS_TRUE(g_execute_complete_called);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_on_bytes_recv_GET_failure)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    size_t buffer_len = strlen(TEST_HTTP_GET_BUFFER);
    const unsigned char* buffer = (const unsigned char*)TEST_HTTP_GET_BUFFER;

    setup_httpapi_on_bytes_recv_mocks(8, true);

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 0 };

    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_on_bytes_recv_GET failure in test %zu", index);

        g_on_bytes_recv(g_on_bytes_recv_ctx, buffer, buffer_len);

        //assert
        ASSERT_IS_TRUE(g_execute_complete_called);
    }

    // Cleanup
    HTTPAPI_CloseConnection(handle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(httpapi_on_bytes_recv_HEAD_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    size_t buffer_len = strlen(TEST_HTTP_HEAD_BUFFER);
    const unsigned char* buffer = (const unsigned char*)TEST_HTTP_HEAD_BUFFER;

    setup_httpapi_on_bytes_recv_mocks(8, false);

    //act
    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    g_on_bytes_recv(g_on_bytes_recv_ctx, buffer, buffer_len);

    //assert
    ASSERT_IS_TRUE(g_execute_complete_called);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_on_bytes_recv_HEAD_failures)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    size_t buffer_len = strlen(TEST_HTTP_HEAD_BUFFER);
    const unsigned char* buffer = (const unsigned char*)TEST_HTTP_HEAD_BUFFER;

    setup_httpapi_on_bytes_recv_mocks(8, false);

    umock_c_negative_tests_snapshot();

//    size_t calls_cannot_fail[] = { 0 };

    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        /*if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
            continue;
        }*/

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_on_bytes_recv_GET failure in test %zu", index);

        g_on_bytes_recv(g_on_bytes_recv_ctx, buffer, buffer_len);

        //assert
        //ASSERT_IS_TRUE(g_execute_complete_called);
    }

    // Cleanup
    HTTPAPI_CloseConnection(handle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(httpapi_on_bytes_recv_PUT_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_PUT, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    size_t buffer_len = strlen(TEST_HTTP_PUT_BUFFER);
    const unsigned char* buffer = (const unsigned char*)TEST_HTTP_PUT_BUFFER;

    setup_httpapi_on_bytes_recv_mocks(5, false);

    //act
    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    g_on_bytes_recv(g_on_bytes_recv_ctx, buffer, buffer_len);

    //assert
    ASSERT_IS_TRUE(g_execute_complete_called);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_on_bytes_recv_PUT_failures)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, DEFAULT_HTTP_SECURE_PORT);
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    umock_c_reset_all_calls();

    size_t buffer_len = strlen(TEST_HTTP_PUT_BUFFER);
    const unsigned char* buffer = (const unsigned char*)TEST_HTTP_PUT_BUFFER;

    setup_httpapi_on_bytes_recv_mocks(5, false);

    umock_c_negative_tests_snapshot();

    //    size_t calls_cannot_fail[] = { 0 };

    ASSERT_IS_NOT_NULL(g_on_bytes_recv);
    ASSERT_IS_NOT_NULL(g_on_bytes_recv_ctx);

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        /*if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail)/sizeof(calls_cannot_fail[0])) != 0)
        {
        continue;
        }*/

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "httpapi_on_bytes_recv_PUT failure in test %zu", index);

        g_on_bytes_recv(g_on_bytes_recv_ctx, buffer, buffer_len);

        //assert
        //ASSERT_IS_TRUE(g_execute_complete_called);
    }

    // Cleanup
    HTTPAPI_CloseConnection(handle);
    umock_c_negative_tests_deinit();
}

END_TEST_SUITE(httpapi_unittests);


// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include <stddef.h>

#include "testrunnerswitcher.h"
#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_stdint.h"

static size_t g_current_alloc_calls;
static size_t g_fail_alloc_calls;
static const char* TEST_HOSTNAME = "www.hostname.com";

void* my_gballoc_malloc(size_t size)
{
    void* alloc_result;
    g_current_alloc_calls++;
    if (g_fail_alloc_calls != 0 && g_current_alloc_calls >= g_fail_alloc_calls)
    {
        alloc_result = NULL;
    }
    else
    {
        alloc_result = malloc(size);
    }
    return alloc_result;
}

void my_gballoc_free(void* ptr)
{
    if (ptr != TEST_HOSTNAME)
    {
        free(ptr);
    }
}

#define ENABLE_MOCKS

//#include "umock_c_prod.h"
//#include "umock_c.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/httpheaders.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/constbuffer.h"

#undef ENABLE_MOCKS

#include "azure_c_shared_utility/httpapi.h"

TEST_DEFINE_ENUM_TYPE(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)
IMPLEMENT_UMOCK_C_ENUM_TYPE(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES);

static const XIO_HANDLE TEST_IO_HANDLE = (XIO_HANDLE)0x11;
static const unsigned char* TEST_BUFFER_U_CHAR = (const unsigned char*)0x12;
static size_t TEST_BUFFER_SIZE = 12;
static const CONSTBUFFER_HANDLE TEST_CONSTBUFFER_VALUE = (CONSTBUFFER_HANDLE)0x13;
static const HTTP_HEADERS_HANDLE TEST_HEADER_HANDLE = (HTTP_HEADERS_HANDLE)0x14;

//ON_PACKET_COMPLETE_CALLBACK g_packetComplete;
ON_IO_OPEN_COMPLETE g_openComplete;
ON_BYTES_RECEIVED g_bytesRecv;
ON_IO_ERROR g_ioError;
ON_SEND_COMPLETE g_sendComplete;
void* g_onCompleteCtx;
void* g_onSendCtx;
void* g_bytesRecvCtx;
void* g_ioErrorCtx;

static int g_when_call_to_xio_fail = 0;
static int g_calls_to_xio_send = 0;
static TEST_MUTEX_HANDLE test_serialize_mutex;

static bool g_string_construct_fails = false;
static size_t g_header_count = 0;
static HTTP_HEADERS_RESULT g_header_result = HTTP_HEADERS_OK;
static HTTP_HEADERS_RESULT g_hdr_result = HTTP_HEADERS_OK;

static const size_t TEXT_CONTENT_LENGTH = 70;

static const char* TEST_STRING_VALUE = "Test string value";
static const char* TEST_CERTIFICATE_VALUE = "Test certificate Info";
static const char* TEST_RELATIVE_PATH = "/";
static const unsigned char* TEST_HTTP_CONTENT = (const unsigned char*)"grant_type=client_credentials&client_id=d14d2b5&client_secret=shhhhhh";
static const char* OPTION_TRUSTED_CERTS = "TrustedCerts";
static const char* OPTION_LOG_TRACE = "logtrace";
static const char* INVALID_OPTION_LOG_TRACE = "invalid_option";

#ifdef __cplusplus
extern "C" {
#endif
    static HTTP_HEADERS_HANDLE my_HTTPHeaders_Alloc(void)
    {
        //return (HTTP_HEADERS_HANDLE)my_gballoc_malloc(1);
        return NULL;
    }

    static void my_HTTPHeaders_Free(HTTP_HEADERS_HANDLE h)
    {
        (void)h;
        //my_gballoc_free(h);
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
            *destination = (char*)malloc(len+1);
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

    HTTP_HEADERS_RESULT my_HTTPHeaders_GetHeaderCount(HTTP_HEADERS_HANDLE handle, size_t* headerCount)
    {
        (void)handle;
        *headerCount = g_header_count;
        return g_header_result;
    }

    BUFFER_HANDLE my_BUFFER_new(void)
    {
        return (BUFFER_HANDLE)malloc(1);
    }

    void my_BUFFER_delete(BUFFER_HANDLE handle)
    {
        free(handle);
    }

    STRING_HANDLE my_STRING_construct(const char* psz)
    {
        (void)psz;
        STRING_HANDLE rtn_value;
        if (g_string_construct_fails)
        {
            rtn_value = NULL;
        }
        else
        {
            rtn_value = (STRING_HANDLE)malloc(1);
        }
        return rtn_value;
    }

    void my_STRING_delete(STRING_HANDLE handle)
    {
        free(handle);
    }

    int my_xio_open(XIO_HANDLE handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
    {
        (void)handle;
        g_openComplete = on_io_open_complete;
        g_onCompleteCtx = on_io_open_complete_context;
        g_bytesRecv = on_bytes_received;
        g_bytesRecvCtx = on_bytes_received_context;
        g_ioError = on_io_error;
        g_ioErrorCtx = on_io_error_context;
        return 0;
    }

    int my_xio_send(XIO_HANDLE xio, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
    {
        int send_result = 0;
        (void)xio;
        (void)buffer;
        (void)size;
        g_sendComplete = on_send_complete;
        g_onSendCtx = callback_context;

        g_calls_to_xio_send++;
        if (g_when_call_to_xio_fail > 0 && g_calls_to_xio_send >= g_when_call_to_xio_fail)
        {
            send_result = __LINE__;
        }

        return send_result;
    }

    int my_mallocAndStrcpy_s(char** destination, const char* source)
    {
        (void)source;
        //size_t l = strlen(source);
        //*destination = (char*)malloc(l + 1);
        //strcpy(*destination, source);
        *destination = (char*)TEST_HOSTNAME;
        return 0;
    }

#ifdef __cplusplus
}
#endif

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    (void)error_code;
    ASSERT_FAIL("umock_c reported error");
}

BEGIN_TEST_SUITE(httpapi_unittests)

TEST_SUITE_INITIALIZE(suite_init)
{
    int result;

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

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_Alloc, my_HTTPHeaders_Alloc);
    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_Free, my_HTTPHeaders_Free);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_AddHeaderNameValuePair, HTTP_HEADERS_OK);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_ReplaceHeaderNameValuePair, HTTP_HEADERS_OK);

    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_GetHeader, my_HTTPHeaders_GetHeader);
    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_GetHeaderCount, my_HTTPHeaders_GetHeaderCount);

    REGISTER_GLOBAL_MOCK_HOOK(BUFFER_new, my_BUFFER_new);
    REGISTER_GLOBAL_MOCK_HOOK(BUFFER_delete, my_BUFFER_delete);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_u_char, (unsigned char*)TEST_BUFFER_U_CHAR);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_length, TEST_BUFFER_SIZE);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_build, 0);

    REGISTER_GLOBAL_MOCK_HOOK(xio_open, my_xio_open);
    REGISTER_GLOBAL_MOCK_HOOK(xio_send, my_xio_send);
    REGISTER_GLOBAL_MOCK_RETURN(xio_close, 0);
    //REGISTER_GLOBAL_MOCK_RETURN(xio_dowork, 0);

    //REGISTER_GLOBAL_MOCK_RETURN(mallocAndStrcpy_s, 0);
    REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, my_mallocAndStrcpy_s);
    REGISTER_GLOBAL_MOCK_HOOK(STRING_construct, my_STRING_construct);
    REGISTER_GLOBAL_MOCK_HOOK(STRING_delete, my_STRING_delete);
    REGISTER_GLOBAL_MOCK_RETURN(STRING_c_str, TEST_STRING_VALUE);
    REGISTER_GLOBAL_MOCK_RETURN(STRING_concat, 0);

    REGISTER_GLOBAL_MOCK_RETURN(CONSTBUFFER_Create, TEST_CONSTBUFFER_VALUE);
    //REGISTER_GLOBAL_MOCK_RETURN(BUFFER_build, 0);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    TEST_MUTEX_ACQUIRE(test_serialize_mutex);

    g_string_construct_fails = false;
    g_openComplete = NULL;
    g_onCompleteCtx = NULL;
    g_sendComplete = NULL;
    g_onSendCtx = NULL;
    g_calls_to_xio_send = 0;
    g_when_call_to_xio_fail = 0;
    g_bytesRecv = NULL;
    g_ioError = NULL;
    g_bytesRecvCtx = NULL;
    g_ioErrorCtx = NULL;
    g_fail_alloc_calls = 0;
    g_current_alloc_calls = 0;
    g_header_count = 0;
    g_header_result = HTTP_HEADERS_OK;
    g_string_construct_fails = false;
    g_hdr_result = HTTP_HEADERS_OK;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    umock_c_reset_all_calls();
    TEST_MUTEX_RELEASE(test_serialize_mutex);
}

static void my_on_execute_complete(void* callback_context, HTTPAPI_RESULT execute_result, unsigned int statusCode, HTTP_HEADERS_HANDLE respHeader, CONSTBUFFER_HANDLE responseBuffer)
{
    (void)callback_context;
    (void)execute_result;
    (void)statusCode;
    (void)respHeader;
    (void)responseBuffer;
}

TEST_FUNCTION(httpapi_createconnection_hostname_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle;

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, NULL, 443);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

TEST_FUNCTION(httpapi_createconnection_XIO_HANDLE_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle;

    //act
    handle = HTTPAPI_CreateConnection(NULL, TEST_HOSTNAME, 443);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

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
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, invalid_hostname, 443);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

TEST_FUNCTION(httpapi_createconnection_allocation_fail)
{
    //arrange
    HTTP_HANDLE handle;

    g_fail_alloc_calls = 1;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_createconnection_mallocAndStrcpy_fail)
{
    //arrange
    HTTP_HANDLE handle;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_NUM_ARG, TEST_HOSTNAME))
        .IgnoreArgument(1)
        .SetReturn(__LINE__);
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_createconnection_xio_open_fail)
{
    //arrange
    HTTP_HANDLE handle;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_NUM_ARG, TEST_HOSTNAME))
        .IgnoreArgument(1);
        //.CopyOutArgumentBuffer(1, &TEST_HOSTNAME, sizeof(TEST_HOSTNAME) );
    STRICT_EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5)
        .IgnoreArgument(6)
        .IgnoreArgument(7)
        .SetReturn(__LINE__);
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_createconnection_succeed)
{
    //arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_NUM_ARG, TEST_HOSTNAME))
        .IgnoreArgument(1);
    EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    //act
    HTTP_HANDLE http_handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);

    //assert
    ASSERT_IS_NOT_NULL(http_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(http_handle);
}

TEST_FUNCTION(httpapi_closeconnection_handle_null_succeed)
{
    //arrange

    //act
    HTTPAPI_CloseConnection(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_closeconnection_with_certificate_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_SetOption(handle, "logtrace", TEST_CERTIFICATE_VALUE), HTTPAPI_OK);

    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    HTTPAPI_CloseConnection(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_closeconnection_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    HTTPAPI_CloseConnection(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

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

TEST_FUNCTION(httpapi_executerequestasync_relativePath_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, NULL, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_content_NULL_contentLength_valid_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_content_valid_contentLength_0_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, TEST_HTTP_CONTENT, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_invalid_state_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
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

TEST_FUNCTION(httpapi_executerequestasync_string_proc_alloc_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    g_fail_alloc_calls = 2;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_STRING_PROCESSING_ERROR, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_string_construct_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    g_string_construct_fails = true;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_ALLOC_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_xio_send_returns_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    g_when_call_to_xio_fail = 1;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_SEND_REQUEST_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_GET_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_GET_content_len_request_included_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    g_header_count = 4;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));

    for (size_t index = 0; index < g_header_count; index++)
    {
        EXPECTED_CALL(HTTPHeaders_GetHeader(TEST_HEADER_HANDLE, 0, IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_GET_host_request_included_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    g_header_count = 3;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));

    for (size_t index = 0; index < g_header_count; index++)
    {
        EXPECTED_CALL(HTTPHeaders_GetHeader(TEST_HEADER_HANDLE, 0, IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
        EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
        EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    }

    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_GetHeader_return_ERROR_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));
    EXPECTED_CALL(HTTPHeaders_GetHeader(TEST_HEADER_HANDLE, 0, IGNORED_PTR_ARG));

    EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));

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

TEST_FUNCTION(httpapi_executerequestasync_GetHeaderCount_return_0_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));

    EXPECTED_CALL(STRING_delete(IGNORED_PTR_ARG));

    g_header_result = HTTP_HEADERS_ERROR;
    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_GET, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_HTTP_HEADERS_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_HEAD_type_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_HEAD, TEST_RELATIVE_PATH, NULL, NULL, 0, NULL, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_POST_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 80);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeader(TEST_HEADER_HANDLE, 0, IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    g_header_count = 1;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_POST, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_POST_string_concat_return_0_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG))
        .SetReturn(__LINE__);
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    g_header_count = 1;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_POST, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_STRING_PROCESSING_ERROR, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_DELETE_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    g_header_count = 0;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_DELETE, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_PUT_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 80);
    umock_c_reset_all_calls();

    g_header_count = 3;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));

    for (size_t index = 0; index < g_header_count; index++)
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
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_POST, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_content_send_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 80);
    umock_c_reset_all_calls();

    g_header_count = 3;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    EXPECTED_CALL(HTTPHeaders_GetHeaderCount(TEST_HEADER_HANDLE, IGNORED_PTR_ARG));

    for (size_t index = 0; index < g_header_count; index++)
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
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    g_when_call_to_xio_fail = 2;

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_POST, TEST_RELATIVE_PATH, TEST_HEADER_HANDLE, TEST_HTTP_CONTENT, TEXT_CONTENT_LENGTH, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_SEND_REQUEST_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_CONNECT_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_CONNECT, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_OPTIONS_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_OPTIONS, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_executerequestasync_TRACE_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_construct(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(STRING_concat(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(xio_send(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5);

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_ExecuteRequestAsync(handle, HTTPAPI_REQUEST_TRACE, TEST_RELATIVE_PATH, NULL, NULL, 0, my_on_execute_complete, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_doWork_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(xio_dowork(TEST_IO_HANDLE));

    //act
    HTTPAPI_DoWork(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_doWork_handle_NULL_fail)
{
    //arrange

    //act
    HTTPAPI_DoWork(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_setoption_handle_NULL_fail)
{
    //arrange

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(NULL, OPTION_TRUSTED_CERTS, (const void*)TEST_CERTIFICATE_VALUE);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_setoption_option_name_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
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

TEST_FUNCTION(httpapi_setoption_unknown_option_name_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
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

TEST_FUNCTION(httpapi_setoption_trusted_certs_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_TRUSTED_CERTS, (const void*)TEST_CERTIFICATE_VALUE);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_setoption_trusted_certs_alloc_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    g_fail_alloc_calls = 2;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_TRUSTED_CERTS, (const void*)TEST_CERTIFICATE_VALUE);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_ALLOC_FAILED, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_setoption_trusted_certs_NULL_value_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_TRUSTED_CERTS, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_setoption_trusted_certs_2_calls_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_TRUSTED_CERTS, (const void*)TEST_CERTIFICATE_VALUE);
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);

    umock_c_reset_all_calls();

    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    //act
    http_result = HTTPAPI_SetOption(handle, OPTION_TRUSTED_CERTS, (const void*)TEST_CERTIFICATE_VALUE);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_setoption_log_trace_value_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
    umock_c_reset_all_calls();

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_SetOption(handle, OPTION_LOG_TRACE, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_setoption_log_trace_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME, 443);
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

TEST_FUNCTION(httpapi_cloneoption_optionName_NULL_fail)
{
    //arrange

    //act
    char* cert = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(NULL, TEST_CERTIFICATE_VALUE, (const void**)&cert);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_IS_NULL(cert);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_cloneoption_value_NULL_fail)
{
    //arrange

    //act
    char* cert = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_TRUSTED_CERTS, NULL, (const void**)&cert);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_IS_NULL(cert);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_cloneoption_savedvalue_NULL_fail)
{
    //arrange

    //act
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_TRUSTED_CERTS, TEST_CERTIFICATE_VALUE, NULL);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_INVALID_ARG, http_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_cloneoption_trusted_cert_alloc_fail)
{
    //arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    g_fail_alloc_calls = 1;

    //act
    char* cert = NULL;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_TRUSTED_CERTS, TEST_CERTIFICATE_VALUE, (const void**)&cert);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_ALLOC_FAILED, http_result);
    ASSERT_IS_NULL(cert);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
}

TEST_FUNCTION(httpapi_cloneoption_trusted_cert_succeed)
{
    //arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    //act
    char* cert;
    HTTPAPI_RESULT http_result = HTTPAPI_CloneOption(OPTION_TRUSTED_CERTS, TEST_CERTIFICATE_VALUE, (const void**)&cert);

    //assert
    ASSERT_ARE_EQUAL(HTTPAPI_RESULT, HTTPAPI_OK, http_result);
    ASSERT_IS_NOT_NULL(cert);
    ASSERT_ARE_EQUAL(char_ptr, TEST_CERTIFICATE_VALUE, cert);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    free(cert);
}

TEST_FUNCTION(httpapi_cloneoption_logtrace_alloc_fail)
{
    //arrange
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    g_fail_alloc_calls = 1;

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

END_TEST_SUITE(httpapi_unittests);


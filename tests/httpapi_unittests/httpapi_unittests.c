// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "testrunnerswitcher.h"
#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_stdint.h"

static int g_fail_alloc_calls;

void* my_gballoc_malloc(size_t size)
{
    void* alloc_result;
    if (g_fail_alloc_calls != 0)
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
    free(ptr);
}

#define ENABLE_MOCKS

#include "umock_c_prod.h"
#include "umock_c.h"
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

static const XIO_HANDLE TEST_IO_HANDLE = (XIO_HANDLE)0x11;
static const unsigned char* TEST_BUFFER_U_CHAR = (const unsigned char*)0x12;
static size_t TEST_BUFFER_SIZE = 12;
static const CONSTBUFFER_HANDLE TEST_CONSTBUFFER_VALUE = (CONSTBUFFER_HANDLE)0x13;

//ON_PACKET_COMPLETE_CALLBACK g_packetComplete;
ON_IO_OPEN_COMPLETE g_openComplete;
ON_BYTES_RECEIVED g_bytesRecv;
ON_IO_ERROR g_ioError;
ON_SEND_COMPLETE g_sendComplete;
void* g_onCompleteCtx;
void* g_onSendCtx;
void* g_bytesRecvCtx;
void* g_ioErrorCtx;

static TEST_MUTEX_HANDLE test_serialize_mutex;

static bool malloc_will_fail = false;

static const char* TEST_HOSTNAME = "www.hostname.com";
static const char* TEST_STRING_VALUE = "Test string value";

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    (void)error_code;
    ASSERT_FAIL("umock_c reported error");
}

static HTTP_HEADERS_HANDLE my_HTTPHeaders_Alloc(void)
{
    return (HTTP_HEADERS_HANDLE)my_gballoc_malloc(1);
}

static void my_HTTPHeaders_Free(HTTP_HEADERS_HANDLE h)
{
    my_gballoc_free(h);
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
    return (STRING_HANDLE)malloc(1);
}

void my_STRING_delete(STRING_HANDLE handle)
{
    free(handle);
}

int my_xio_open(XIO_HANDLE handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    (void)handle;
    /* Bug? : This is a bit wierd, why are we not using on_io_error and on_bytes_received? */
    (void)on_bytes_received;
    (void)on_bytes_received_context;
    (void)on_io_error;
    (void)on_io_error_context;
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
    (void)xio;
    (void)buffer;
    (void)size;
    g_sendComplete = on_send_complete;
    g_onSendCtx = callback_context;
    return 0;
}

int my_mallocAndStrcpy_s(char** destination, const char* source)
{
    size_t l = strlen(source);
    *destination = (char*)malloc(l + 1);
    strcpy(*destination, source);
    return 0;
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

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_Alloc, my_HTTPHeaders_Alloc);
    REGISTER_GLOBAL_MOCK_HOOK(HTTPHeaders_Free, my_HTTPHeaders_Free);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_AddHeaderNameValuePair, HTTP_HEADERS_OK);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_ReplaceHeaderNameValuePair, HTTP_HEADERS_OK);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_GetHeader, HTTP_HEADERS_OK);
    REGISTER_GLOBAL_MOCK_RETURN(HTTPHeaders_GetHeaderCount, HTTP_HEADERS_OK);

    REGISTER_GLOBAL_MOCK_HOOK(BUFFER_new, my_BUFFER_new);
    REGISTER_GLOBAL_MOCK_HOOK(BUFFER_delete, my_BUFFER_delete);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_u_char, (unsigned char*)TEST_BUFFER_U_CHAR);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_length, TEST_BUFFER_SIZE);
    REGISTER_GLOBAL_MOCK_RETURN(BUFFER_build, 0);

    REGISTER_GLOBAL_MOCK_HOOK(xio_open, my_xio_open);
    REGISTER_GLOBAL_MOCK_HOOK(xio_send, my_xio_send);
    REGISTER_GLOBAL_MOCK_RETURN(xio_close, 0);
    //REGISTER_GLOBAL_MOCK_RETURN(xio_dowork, 0);

    REGISTER_GLOBAL_MOCK_HOOK(mallocAndStrcpy_s, my_mallocAndStrcpy_s);
    REGISTER_GLOBAL_MOCK_HOOK(STRING_construct, my_STRING_construct);
    REGISTER_GLOBAL_MOCK_HOOK(STRING_delete, my_STRING_delete);
    REGISTER_GLOBAL_MOCK_RETURN(STRING_c_str, TEST_STRING_VALUE);

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
    malloc_will_fail = false;
    g_openComplete = NULL;
    g_onCompleteCtx = NULL;
    g_sendComplete = NULL;
    g_onSendCtx = NULL;
    g_bytesRecv = NULL;
    g_ioError = NULL;
    g_bytesRecvCtx = NULL;
    g_ioErrorCtx = NULL;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    umock_c_reset_all_calls();
    TEST_MUTEX_RELEASE(test_serialize_mutex);
}

TEST_FUNCTION(httpapi_CreateConnection_hostname_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle;

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, NULL);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

TEST_FUNCTION(httpapi_CreateConnection_XIO_HANDLE_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle;

    //act
    handle = HTTPAPI_CreateConnection(NULL, TEST_HOSTNAME);

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
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, invalid_hostname);

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
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME);

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
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME);

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
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_NUM_ARG, TEST_HOSTNAME)).IgnoreArgument(1);
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
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

TEST_FUNCTION(httpapi_createconnection_succeed)
{
    //arrange
    HTTP_HANDLE handle;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(mallocAndStrcpy_s(IGNORED_NUM_ARG, TEST_HOSTNAME))
        .IgnoreArgument(1);
    EXPECTED_CALL(xio_open(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG))
        .IgnoreArgument(2)
        .IgnoreArgument(3)
        .IgnoreArgument(4)
        .IgnoreArgument(5)
        .IgnoreArgument(6)
        .IgnoreArgument(7);

    //act
    handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME);

    //assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
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

TEST_FUNCTION(httpapi_closeconnection_succeed)
{
    //arrange
    HTTP_HANDLE handle = HTTPAPI_CreateConnection(TEST_IO_HANDLE, TEST_HOSTNAME);
    umock_c_reset_all_calls();

    EXPECTED_CALL(xio_close(TEST_IO_HANDLE, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    HTTPAPI_CloseConnection(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // Cleanup
    HTTPAPI_CloseConnection(handle);
}

END_TEST_SUITE(httpapi_unittests);


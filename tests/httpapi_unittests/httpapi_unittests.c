// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

void my_gballoc_free(void* ptr)
{
    free(ptr);
}

#include "testrunnerswitcher.h"
#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_stdint.h"

#define ENABLE_MOCKS

#include "umock_c_prod.h"
#include "umock_c.h"
#include "azure_c_shared_utility/gballoc.h"

#undef ENABLE_MOCKS

#include "azure_c_shared_utility/httpapi.h"

TEST_DEFINE_ENUM_TYPE(HTTPAPI_RESULT, HTTPAPI_RESULT_VALUES)

static TEST_MUTEX_HANDLE test_serialize_mutex;

static bool malloc_will_fail = false;

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

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);
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
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    umock_c_reset_all_calls();
    TEST_MUTEX_RELEASE(test_serialize_mutex);
}

// Tests_SRS_CONDITION_18_002: [ Condition_Init shall create and return a CONDITION_HANDLE ]
TEST_FUNCTION(httpapi_CreateConnection_hostname_NULL_fail)
{
    //arrange
    HTTP_HANDLE handle = NULL;

    //act
    handle = HTTPAPI_CreateConnection(NULL);

    //assert
    ASSERT_IS_NULL(handle);

    // Cleanup
}

END_TEST_SUITE(httpapi_unittests);


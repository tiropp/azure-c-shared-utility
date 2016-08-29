// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

void* my_gballoc_malloc(size_t size)
{
    void *result = malloc(size);
    return result;
}

void my_gballoc_free(void* ptr)
{
    free(ptr);
}

static void my_remove_callback(void* queue_item)
{
    (void)queue_item;
}

#include "testrunnerswitcher.h"
#include "azure_c_shared_utility/macro_utils.h"

#include "umock_c.h"
#include "umock_c_negative_tests.h"
#include "umocktypes.h"
#include "umocktypes_c.h"


#define ENABLE_MOCKS

#include "azure_c_shared_utility/gballoc.h"

MOCKABLE_FUNCTION(, void, remove_callback, void*, queue_item);

#undef ENABLE_MOCKS

#include "azure_c_shared_utility/queue.h"

static const void* TEST_QUEUE_ITEM_1 = (void*)0x11;
static const void* TEST_QUEUE_ITEM_2 = (void*)0x12;
static const void* TEST_QUEUE_ITEM_3 = (void*)0x13;
static const void* TEST_QUEUE_ITEM_4 = (void*)0x14;
static const void* TEST_QUEUE_ITEM_5 = (void*)0x15;

static TEST_MUTEX_HANDLE g_testByTest;
static TEST_MUTEX_HANDLE g_dllByDll;

TEST_DEFINE_ENUM_TYPE(QUEUE_RESULT, QUEUE_RESULT_VALUES);
IMPLEMENT_UMOCK_C_ENUM_TYPE(QUEUE_RESULT, QUEUE_RESULT_VALUES);

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s", ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

BEGIN_TEST_SUITE(queue_ut)

TEST_SUITE_INITIALIZE(TestClassInitialize)
{
    TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    umock_c_init(on_umock_c_error);

    REGISTER_TYPE(QUEUE_RESULT, QUEUE_RESULT);

    REGISTER_UMOCK_ALIAS_TYPE(QUEUE_HANDLE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);
    REGISTER_GLOBAL_MOCK_HOOK(remove_callback, my_remove_callback);
}

TEST_SUITE_CLEANUP(TestClassCleanup)
{
    umock_c_deinit();

    TEST_MUTEX_DESTROY(g_testByTest);
    TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
}

TEST_FUNCTION_INITIALIZE(TestMethodInitialize)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("our mutex is ABANDONED. Failure in test framework");
    }
    umock_c_reset_all_calls();
}

TEST_FUNCTION_CLEANUP(TestMethodCleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
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

/* Tests_SRS_QUEUE_07_002: [On Success Queue_Create shall return a non-NULL handle that refers to a Queue.] */
TEST_FUNCTION(Queue_Create_Succeed)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    //act
    QUEUE_HANDLE handle = Queue_Create(remove_callback);

    //assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_001: [If an error is encountered Queue_Create shall return NULL.] */
TEST_FUNCTION(Queue_Create_fails)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    umock_c_negative_tests_snapshot();

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "Queue_Create failure in test %zu/%zu", index, count);

        QUEUE_HANDLE handle = Queue_Create(remove_callback);

        //assert
        ASSERT_IS_NULL(handle);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Codes_SRS_QUEUE_07_003: [If handle is NULL then Queue_Destroy shall do nothing.] */
TEST_FUNCTION(Queue_Destroy_NULL_handle_fails)
{
    //arrange

    //act
    Queue_Destroy(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_004: [Queue_Destroy shall only free memory allocated within this compilation unit.] */
TEST_FUNCTION(Queue_Destroy_Empty_List_Succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument(1);

    //act
    Queue_Destroy(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_005: [If destroy_callback is not NULL, Queue_Destroy shall call destroy_callback with the item to be deleted.] */
TEST_FUNCTION(Queue_Destroy_nonEmpty_List_Succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    Queue_Destroy(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_006: [If handle or queue_item are NULL Queue_Enqueue_Item shall return QUEUE_INVALID_ARG.] */
TEST_FUNCTION(Queue_Enqueue_Item_NULL_handle_fails)
{
    //arrange

    //act
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(NULL, (void*)TEST_QUEUE_ITEM_1);

    //assert
    ASSERT_ARE_NOT_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_006: [If handle or queue_item are NULL Queue_Enqueue_Item shall return QUEUE_INVALID_ARG.] */
TEST_FUNCTION(Queue_Enqueue_Item_NULL_queue_item_fails)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    //act
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, NULL);

    //assert
    ASSERT_ARE_NOT_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_007: [Queue_Enqueue_Item shall allocate an queue item and store the item into the queue.] */
/* Tests_SRS_QUEUE_07_008: [On success Queue_Enqueue_Item shall return QUEUE_OK.] */
TEST_FUNCTION(Queue_Enqueue_Item_succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    //act
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_009: [If any error is encountered Queue_Enqueue_Item shall return QUEUE_ERROR.] */
TEST_FUNCTION(Queue_Enqueue_Item_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    umock_c_negative_tests_snapshot();

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "Queue_Create failure in test %zu/%zu", index, count);

        QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);

        //assert
        ASSERT_ARE_NOT_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    }

    //cleanup
    Queue_Destroy(handle);
    umock_c_negative_tests_deinit();
}

/* Tests_SRS_QUEUE_07_010: [If handle is NULL Queue_Get_Item shall return NULL.] */
TEST_FUNCTION(Queue_Get_Item_NULL_handle_fail)
{
    //arrange

    //act
    const void* client_queue_item = Queue_Get_Item(NULL);

    //assert
    ASSERT_IS_NULL(client_queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_012: [If the QUEUE_ITEM is retrieved from the queue Queue_Get_Item shall return a const QUEUE_ITEM.] */
TEST_FUNCTION(Queue_Get_Item_succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    //act
    const void* client_queue_item = Queue_Get_Item(handle);

    //assert
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, client_queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_012: [If the QUEUE_ITEM is retrieved from the queue Queue_Get_Item shall return a const QUEUE_ITEM.] */
TEST_FUNCTION(Queue_Get_Item_always_return_item_succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_3);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    //act
    const void* client_queue_item = Queue_Get_Item(handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, client_queue_item);

    const void* client_queue_item_2nd = Queue_Get_Item(handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, client_queue_item_2nd);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_012: [If the QUEUE_ITEM is retrieved from the queue Queue_Get_Item shall return a const QUEUE_ITEM.] */
TEST_FUNCTION(Queue_Get_Item_returns_proper_item_after_removal_succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_3);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    const void* client_queue_item = Queue_Get_Item(handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, client_queue_item);

    const void* client_queue_item_2nd = Queue_Get_Item(handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, client_queue_item_2nd);

    queue_result = Queue_Dequeue_Item(handle);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    const void* client_queue_item_3nd = Queue_Get_Item(handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_2, client_queue_item_3nd);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_011: [If the queue is empty, Queue_Get_Item shall return NULL.] */
TEST_FUNCTION(Queue_Get_Item_empty_queue_fail)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    //act
    const void* client_queue_item = Queue_Get_Item(handle);

    //assert
    ASSERT_IS_NULL(client_queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_013: [If handle is NULL Queue_Dequeue_Item shall return QUEUE_INVALID_ARG.] */
TEST_FUNCTION(Queue_Dequeue_Item_NULL_handle_fail)
{
    //arrange

    //act
    QUEUE_RESULT queue_result = Queue_Dequeue_Item(NULL);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_INVALID_ARG, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_016: [On success Queue_Dequeue_Item shall return QUEUE_OK.] */
/* Tests_SRS_QUEUE_07_015: [If the Item is successfully Removed from the queue and destroy_callback is not NULL, Queue_Dequeue_Item will call destroy_callback and deallocate the item.] */
TEST_FUNCTION(Queue_Dequeue_Item_succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    queue_result = Queue_Dequeue_Item(handle);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}


/* Tests_SRS_QUEUE_07_032: [ If remove_callback is not NULL, Queue_Enum_Dequeue_Item shall call remove_callback with current enumerated item. ] */
TEST_FUNCTION(Queue_Dequeue_Item_off_the_end_of_list_Succeed)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    queue_result = Queue_Dequeue_Item(handle);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    queue_result = Queue_Dequeue_Item(handle);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_EMPTY, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}


/* Tests_SRS_QUEUE_07_014: [If the queue is empty, Queue_Dequeue_Item shall return QUEUE_EMPTY.] */
TEST_FUNCTION(Queue_Dequeue_Item_on_empty_queue_fail)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    //act
    QUEUE_RESULT queue_result = Queue_Dequeue_Item(handle);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_EMPTY, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_017: [If handle is NULL Queue_Create_Enum shall return NULL.] */
TEST_FUNCTION(Queue_Create_Enum_handle_fail)
{
    //arrange

    //act
    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(NULL);

    //assert
    ASSERT_IS_NULL(enum_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_025: [If the queue referenced by handle is empty Queue_Create_Enum shall return NULL.] */
TEST_FUNCTION(Queue_Create_Enum_on_empty_list_NULL)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    //act
    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

    //assert
    ASSERT_IS_NOT_NULL(enum_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_018: [Queue_Create_Enum shall allocate and initialize the data neccessary for enumeration of the queue.] */
/* Tests_SRS_QUEUE_07_019: [On Success Queue_Create_Enum shall return a QUEUE_ENUM_HANDLE.] */
TEST_FUNCTION(Queue_Create_Enum_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    //act
    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

    //assert
    ASSERT_IS_NOT_NULL(enum_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

TEST_FUNCTION(Queue_Create_Enum_fails)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();
    umock_c_negative_tests_snapshot();

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "Queue_Create_Enum failure in test %zu/%zu", index, count);

        QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

        //assert
        ASSERT_IS_NULL(enum_handle);
    }

    //cleanup
    Queue_Destroy(handle);
    umock_c_negative_tests_deinit();
}

/* Tests_SRS_QUEUE_07_026: [If any error is encountered Queue_Create_Enum shall return NULL.] */
TEST_FUNCTION(Queue_Create_Enum_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    umock_c_negative_tests_snapshot();

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        char tmp_msg[64];
        sprintf(tmp_msg, "Queue_Create_Enum failure in test %zu/%zu", index, count);

        QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

        //assert
        ASSERT_IS_NULL(enum_handle);
    }

    //cleanup
    Queue_Destroy(handle);
    umock_c_negative_tests_deinit();
}

/* Tests_SRS_QUEUE_07_020: [If enum_handle is NULL Queue_Enum_Next_Item shall return NULL.] */
TEST_FUNCTION(Queue_Enum_Next_Item_handle_null_fail)
{
    //arrange
    umock_c_reset_all_calls();

    //act
    void* queue_item = Queue_Enum_Next_Item(NULL);

    //assert
    ASSERT_IS_NULL(queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_021: [If the end of the queue is reached Queue_Enum_Next_Item shall return NULL.] */
TEST_FUNCTION(Queue_Enum_Next_Item_empty_list_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);
    umock_c_reset_all_calls();

    //act
    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_IS_NULL(queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);

    //assert
    ASSERT_IS_NULL(queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_022: [On success Queue_Enum_Next_Item shall return the next queue item from the previous call to Queue_Enum_Next_Item.] */
TEST_FUNCTION(Queue_Enum_Next_Item_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_3);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);
    umock_c_reset_all_calls();

    //act
    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_2, queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_3, queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);

    //assert
    ASSERT_IS_NULL(queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_022: [On success Queue_Enum_Next_Item shall return the next queue item from the previous call to Queue_Enum_Next_Item.] */
TEST_FUNCTION(Queue_Enum_Next_Item_with_addition_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_3);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument_size();

    //act
    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_2, queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_3, queue_item);

    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_4);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    queue_item = Queue_Enum_Next_Item(enum_handle);

    //assert
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_4, queue_item);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_QUEUE_07_023: [If enum_handle is NULL Queue_Enum_Destroy shall do nothing.] */
TEST_FUNCTION(Queue_Enum_Destroy_enum_handle_NULL_success)
{
    //arrange

    //act
    Queue_Enum_Destroy(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_QUEUE_07_024: [Queue_Enum_Destroy shall deallocate any information that has been allocated in Queue_Create_Enum.] */
TEST_FUNCTION(Queue_Enum_Destroy_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    Queue_Enum_Destroy(enum_handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUBCLIENT_LL_07_001: [ If enum_handle is NULL Queue_Enum_Dequeue_Item shall return QUEUE_INVALID_ARG. ] */
TEST_FUNCTION(Queue_Enum_Dequeue_Item_enum_handle_NULL_fail)
{
    //arrange
    umock_c_reset_all_calls();

    //act
    QUEUE_RESULT queue_result = Queue_Enum_Dequeue_Item(NULL);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_INVALID_ARG, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_IOTHUBCLIENT_LL_07_002: [ If the enum_handle has encountered the last item Queue_Enum_Dequeue_Item shall return QUEUE_EMPTY. ] */
TEST_FUNCTION(Queue_Enum_Dequeue_Item_empty_list_fail)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    ASSERT_IS_NOT_NULL(handle);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);
    ASSERT_IS_NOT_NULL(enum_handle);
    umock_c_reset_all_calls();

    //act
    QUEUE_RESULT queue_result = Queue_Enum_Dequeue_Item(enum_handle);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_EMPTY, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUBCLIENT_LL_07_003: [ If destroy_callback is not NULL, Queue_Enum_Dequeue_Item shall call destroy_callback with current enumerated item. ]*/
TEST_FUNCTION(Queue_Enum_Dequeue_Item_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_3);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    queue_result = Queue_Enum_Dequeue_Item(enum_handle);

    queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_3, queue_item);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUBCLIENT_LL_07_004: [ If successful Queue_Enum_Dequeue_Item shall return QUEUE_OK. ] */
TEST_FUNCTION(Queue_Enum_Dequeue_Item_end_of_list_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_3);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);

    queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_2, queue_item);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    queue_result = Queue_Enum_Dequeue_Item(enum_handle);

    queue_item = Queue_Get_Item(handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUBCLIENT_LL_07_004: [ If successful Queue_Enum_Dequeue_Item shall return QUEUE_OK. ] */
TEST_FUNCTION(Queue_Enum_Dequeue_Item_1_in_list_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);

    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    queue_result = Queue_Enum_Dequeue_Item(enum_handle);

    queue_item = Queue_Get_Item(handle);
    ASSERT_IS_NULL(queue_item);

    //assert
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUBCLIENT_LL_07_003: [ If destroy_callback is not NULL, Queue_Enum_Dequeue_Item shall call destroy_callback with current enumerated item. ]*/
TEST_FUNCTION(Queue_Enum_Dequeue_Item_off_end_of_list_fail)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    QUEUE_ENUM_HANDLE enum_handle = Queue_Create_Enum(handle);
    ASSERT_IS_NOT_NULL(enum_handle);

    void* queue_item = Queue_Enum_Next_Item(enum_handle);
    ASSERT_ARE_EQUAL(void_ptr, TEST_QUEUE_ITEM_1, queue_item);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(remove_callback(IGNORED_PTR_ARG))
        .IgnoreArgument_queue_item();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG))
        .IgnoreArgument_ptr();

    //act
    queue_result = Queue_Enum_Dequeue_Item(enum_handle);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);

    queue_result = Queue_Enum_Dequeue_Item(enum_handle);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_EMPTY, queue_result);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Enum_Destroy(enum_handle);
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUB_QUEUE_07_027: [If handle is NULL Queue_Is_Empty shall return true.] */
TEST_FUNCTION(Queue_Is_Empty_NULL_handle_fail)
{
    //arrange
    umock_c_reset_all_calls();

    //act
    bool is_empty = Queue_Is_Empty(NULL);

    //assert
    ASSERT_IS_TRUE(is_empty);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_SRS_IOTHUB_QUEUE_07_029: [...Otherwise it shall return false.] */
TEST_FUNCTION(Queue_Is_Empty_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    QUEUE_RESULT queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_1);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    queue_result = Queue_Enqueue_Item(handle, (void*)TEST_QUEUE_ITEM_2);
    ASSERT_ARE_EQUAL(QUEUE_RESULT, QUEUE_OK, queue_result);
    umock_c_reset_all_calls();

    //act
    bool is_empty = Queue_Is_Empty(handle);

    //assert
    ASSERT_IS_FALSE(is_empty);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

/* Tests_SRS_IOTHUB_QUEUE_07_028: [If the List pointed to by handle is Empty Queue_Is_Empty shall return true...] */
TEST_FUNCTION(Queue_Is_Empty_empty_list_success)
{
    //arrange
    QUEUE_HANDLE handle = Queue_Create(remove_callback);
    umock_c_reset_all_calls();

    //act
    bool is_empty = Queue_Is_Empty(handle);

    //assert
    ASSERT_IS_TRUE(is_empty);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    Queue_Destroy(handle);
}

END_TEST_SUITE(queue_ut)

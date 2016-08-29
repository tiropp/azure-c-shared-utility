// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/** @file iothub_client_version.h
*	@brief Functions for managing the client SDK version.
*/

#ifndef QUEUE_H
#define QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"

typedef struct QUEUE_DATA_TAG* QUEUE_HANDLE;
typedef struct QUEUE_ENUM_TAG* QUEUE_ENUM_HANDLE;

#define QUEUE_RESULT_VALUES     \
    QUEUE_OK,                   \
    QUEUE_INVALID_ARG,          \
    QUEUE_EMPTY,                \
    QUEUE_ERROR                 \

DEFINE_ENUM(QUEUE_RESULT, QUEUE_RESULT_VALUES);

typedef void(*QUEUE_REMOVE_ITEM_CALLBACK)(void* queue_item);

MOCKABLE_FUNCTION(, QUEUE_HANDLE, Queue_Create, QUEUE_REMOVE_ITEM_CALLBACK, remove_callback);
MOCKABLE_FUNCTION(, void, Queue_Destroy, QUEUE_HANDLE, handle);

MOCKABLE_FUNCTION(, bool, Queue_Is_Empty, QUEUE_HANDLE, handle);

MOCKABLE_FUNCTION(, QUEUE_RESULT, Queue_Enqueue_Item, QUEUE_HANDLE, handle, void*, client_queue_item);
MOCKABLE_FUNCTION(, void*, Queue_Get_Item, QUEUE_HANDLE, handle);
MOCKABLE_FUNCTION(, QUEUE_RESULT, Queue_Dequeue_Item, QUEUE_HANDLE, handle);

MOCKABLE_FUNCTION(, QUEUE_ENUM_HANDLE, Queue_Create_Enum, QUEUE_HANDLE, handle);
MOCKABLE_FUNCTION(, void*, Queue_Enum_Next_Item, QUEUE_ENUM_HANDLE, enum_handle);
MOCKABLE_FUNCTION(, QUEUE_RESULT, Queue_Enum_Dequeue_Item, QUEUE_ENUM_HANDLE, enum_handle);
MOCKABLE_FUNCTION(, void, Queue_Enum_Destroy, QUEUE_ENUM_HANDLE, enum_handle);

#ifdef __cplusplus
}
#endif

#endif // QUEUE_H

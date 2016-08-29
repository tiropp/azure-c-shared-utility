// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h> 
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/queue.h"
#include "azure_c_shared_utility/xlogging.h"

typedef struct QUEUE_ITEM_TAG
{
    void* client_queue_item;
    struct QUEUE_ITEM_TAG* next;
} QUEUE_ITEM;

typedef struct QUEUE_DATA_TAG
{
    QUEUE_ITEM* list_entry;
    QUEUE_ITEM* back_item;
    QUEUE_REMOVE_ITEM_CALLBACK remove_callback;
} QUEUE_DATA;

typedef struct QUEUE_ENUM_TAG
{
    QUEUE_DATA* queue_data_item;
    QUEUE_ITEM* current_entry;
    QUEUE_ITEM* prev_entry;  // This is so if we remove the last item then have the second to last item
} QUEUE_ENUM;

static void destroy_front_queue_item(QUEUE_DATA* queue_data)
{
    QUEUE_ITEM* temp_item = queue_data->list_entry->next;
    free(queue_data->list_entry);
    queue_data->list_entry = temp_item;
    if (temp_item == NULL)
    {
        queue_data->back_item = temp_item;
    }
}

QUEUE_HANDLE Queue_Create(QUEUE_REMOVE_ITEM_CALLBACK remove_callback)
{
    QUEUE_DATA* result;
    result = (QUEUE_DATA*)malloc(sizeof(QUEUE_DATA));
    if (result == NULL)
    {
        /* Codes_SRS_QUEUE_07_001: [If an error is encountered Queue_Create_Queue shall return NULL.] */
        LogError("Failure allocating QUEUE_DATA.");
    }
    else
    {
        /* Codes_SRS_QUEUE_07_002: [On Success Queue_Create_Queue shall return a non-NULL handle that refers to a Queue.] */
        result->back_item = result->list_entry = NULL;
        result->remove_callback = remove_callback;
    }
    return result;
}

void Queue_Destroy(QUEUE_HANDLE handle)
{
    /* Codes_SRS_QUEUE_07_003: [If handle is NULL then Queue_Destroy shall do nothing.] */
    if (handle != NULL)
    {
        QUEUE_DATA* queue_data = (QUEUE_DATA*)handle;
        while (!Queue_Is_Empty(handle) )
        {            
            /* Codes_SRS_QUEUE_07_005: [If remove_callback is not NULL, Queue_Destroy shall call remove_callback with the item to be deleted.] */
            if (queue_data->remove_callback != NULL)
            {
                queue_data->remove_callback(queue_data->list_entry->client_queue_item);
            }
            /* Codes_SRS_QUEUE_07_004: [Queue_Destroy shall only free memory allocated within this compilation unit.] */
            destroy_front_queue_item(queue_data);
        }
        free(queue_data);
    }
}

QUEUE_RESULT Queue_Enqueue_Item(QUEUE_HANDLE handle, void* client_queue_item)
{
    QUEUE_RESULT result;
    /* Codes_SRS_QUEUE_07_006: [If handle or client_queue_item are NULL Queue_Enqueue_Item shall return QUEUE_INVALID_ARG.] */
    if (handle == NULL || client_queue_item == NULL)
    {
        LogError("Invalid argument: Handle or client_queue_item are NULL.");
        result = QUEUE_INVALID_ARG;
    }
    else
    {
        QUEUE_ITEM* queue_item = malloc(sizeof(QUEUE_ITEM) );
        if (queue_item == NULL)
        {
            /* Codes_SRS_QUEUE_07_009: [If any error is encountered Queue_Enqueue_Item shall return QUEUE_ERROR.] */
            LogError("Failure allocating QUEUE_ITEM.");
            result = QUEUE_ERROR;
        }
        else
        {
            QUEUE_DATA* queue_data = (QUEUE_DATA*)handle;

            /* Codes_SRS_QUEUE_07_007: [Queue_Enqueue_Item shall allocate an queue item and store the item into the queue.] */
            queue_item->client_queue_item = client_queue_item;
            queue_item->next = NULL;
            if (queue_data->back_item == NULL)
            {
                queue_data->list_entry = queue_data->back_item = queue_item;
            }
            else
            {
                queue_data->back_item->next = queue_item;
            }
            queue_data->back_item = queue_item;;

            /* Codes_SRS_QUEUE_07_008: [On success Queue_Enqueue_Item shall return QUEUE_OK.] */
            result = QUEUE_OK;
        }
    }
    return result;
}

void* Queue_Get_Item(QUEUE_HANDLE handle)
{
    void* result;
    result = NULL;
    /* Codes_SRS_QUEUE_07_010: [If handle is NULL Queue_Get_Item shall return NULL.] */
    if (handle == NULL)
    {
        LogError("Invalid argument: handle is NULL");
        result = NULL;
    }
    else
    {
        QUEUE_DATA* queue_data = (QUEUE_DATA*)handle;
        if (queue_data->list_entry == NULL)
        {
            /* Codes_SRS_QUEUE_07_011: [If the queue is empty, Queue_Get_Item shall return NULL.] */
            result = NULL;
        }
        else
        {
            /* Codes_SRS_QUEUE_07_012: [If the QUEUE_ITEM is retrieved from the queue Queue_Get_Item shall return a const QUEUE_ITEM.] */
            result = queue_data->list_entry->client_queue_item;
        }
    }
    return result;
}

QUEUE_RESULT Queue_Dequeue_Item(QUEUE_HANDLE handle)
{
    QUEUE_RESULT result = QUEUE_INVALID_ARG;
    if (handle == NULL)
    {
        /* Codes_SRS_QUEUE_07_013: [If handle is NULL Queue_Dequeue_Item shall return QUEUE_INVALID_ARG.] */
        LogError("Invalid argument: handle is NULL");
        result = QUEUE_INVALID_ARG;
    }
    else
    {
        QUEUE_DATA* queue_data = (QUEUE_DATA*)handle;
        if (queue_data->list_entry == NULL)
        {
            /* Codes_SRS_QUEUE_07_014: [If the queue is empty, Queue_Dequeue_Item shall return QUEUE_EMPTY.] */
            // Nothing in the list
            result = QUEUE_EMPTY;
        }
        else
        {
            /* Codes_SRS_QUEUE_07_015: [If remove_callback is not NULL, Queue_Dequeue_Item will call remove_callback and deallocate the item.] */
            if (queue_data->remove_callback != NULL)
            {
                queue_data->remove_callback(queue_data->list_entry->client_queue_item);
            }
            destroy_front_queue_item(queue_data);

            /* Codes_SRS_QUEUE_07_016: [On success Queue_Dequeue_Item shall return QUEUE_OK.] */
            result = QUEUE_OK;
        }
    }
    return result;
}

QUEUE_ENUM_HANDLE Queue_Create_Enum(QUEUE_HANDLE handle)
{
    QUEUE_ENUM* result;
    /* Codes_SRS_QUEUE_07_017: [If handle is NULL Queue_Create_Enum shall return NULL.] */
    if (handle == NULL)
    {
        LogError("Invalid argument: handle is NULL");
        result = NULL;
    }
    else
    {
        QUEUE_DATA* queue_data = (QUEUE_DATA*)handle;
        /* Codes_SRS_QUEUE_07_018: [Queue_Create_Enum shall allocate and initialize the data neccessary for enumeration of the queue.] */
        result = (QUEUE_ENUM*)malloc(sizeof(QUEUE_ENUM) );
        if (result == NULL)
        {
            /* Codes_SRS_QUEUE_07_026: [If any error is encountered Queue_Create_Enum shall return NULL.] */
            LogError("unable to allocate Queue Enum");
        }
        else
        {
            /* Codes_SRS_QUEUE_07_019: [On Success Queue_Create_Enum shall return a QUEUE_ENUM_HANDLE.] */
            result->prev_entry = result->current_entry = NULL;
            result->queue_data_item = queue_data;
        }
    }
    return result;
}

QUEUE_RESULT Queue_Enum_Dequeue_Item(QUEUE_ENUM_HANDLE enum_handle)
{
    QUEUE_RESULT result;
    /* Codes_SRS_QUEUE_07_030: [ If enum_handle is NULL Queue_Enum_Dequeue_Item shall return QUEUE_INVALID_ARG. ] */
    if (enum_handle == NULL)
    {
        LogError("Invalid argument: enum_handle=%p", enum_handle);
        result = QUEUE_INVALID_ARG;
    }
    else
    {
        QUEUE_ENUM* queue_enum = (QUEUE_ENUM*)enum_handle;

        /* Codes_SRS_QUEUE_07_031: [ If the enum_handle has encountered the last item Queue_Enum_Dequeue_Item shall return QUEUE_EMPTY. ] */
        if (queue_enum->current_entry == NULL && queue_enum->prev_entry == NULL)
        {
            // The enumeration is empty due to the list being empty
            // Check the queue to make sure items didn't get added
            if (queue_enum->queue_data_item->list_entry != NULL)
            {
                queue_enum->current_entry = queue_enum->queue_data_item->list_entry;
            }
        }

        if (queue_enum->current_entry != NULL)
        {
            /* Codes_SRS_QUEUE_07_032: [ If remove_callback is not NULL, Queue_Enum_Dequeue_Item shall call remove_callback with current enumerated item. ] */
            if (queue_enum->queue_data_item->remove_callback != NULL)
            {
                queue_enum->queue_data_item->remove_callback(queue_enum->current_entry->client_queue_item);
            }
            if (queue_enum->current_entry == queue_enum->queue_data_item->back_item)
            {
                // This Item will be NULL
                queue_enum->queue_data_item->back_item = queue_enum->prev_entry;
                free(queue_enum->current_entry);
                queue_enum->current_entry = NULL;
                if (queue_enum->queue_data_item->back_item != NULL)
                {
                    // There is 
                    queue_enum->queue_data_item->back_item->next = NULL;
                }
                else
                {
                    queue_enum->queue_data_item->list_entry = NULL;
                }
            }
            else
            {
                QUEUE_ITEM* temp_item = queue_enum->current_entry->next;
                free(queue_enum->current_entry);
                if (queue_enum->current_entry == queue_enum->queue_data_item->list_entry)
                {
                    // The dequeued item is the top item, need to move all the items
                    queue_enum->prev_entry = queue_enum->queue_data_item->list_entry = queue_enum->current_entry = temp_item;
                }
                else
                {
                    queue_enum->prev_entry->next = queue_enum->current_entry = temp_item;
                }
            }
            /* Codes_SRS_QUEUE_07_033: [ If successful Queue_Enum_Dequeue_Item shall return QUEUE_OK. ] */
            result = QUEUE_OK;
        }
        else
        {
            /* Codse_SRS_QUEUE_07_034: [If the queue referenced by handle is empty Queue_Create_Enum shall return QUEUE_EMPTY.] */
            result = QUEUE_EMPTY;
        }
    }
    return result;
}

void* Queue_Enum_Next_Item(QUEUE_ENUM_HANDLE enum_handle)
{
    void* result;
    /* Codes_SRS_QUEUE_07_020: [If enum_handle is NULL Queue_Enum_Next_Item shall return NULL.] */
    if (enum_handle == NULL)
    {
        LogError("Invalid argument: handle is NULL");
        result = NULL;
    }
    else
    {
        QUEUE_ENUM* queue_enum = (QUEUE_ENUM*)enum_handle;
        if (queue_enum->current_entry == queue_enum->queue_data_item->back_item)
        {
            /* Codes_SRS_QUEUE_07_021: [If the end of the queue is reached Queue_Enum_Next_Item shall return NULL.] */
            result = NULL;
        }
        else if (queue_enum->current_entry == NULL)
        {
            // Initialize all the items
            queue_enum->prev_entry = NULL;
            queue_enum->current_entry = queue_enum->queue_data_item->list_entry;
            result = queue_enum->current_entry->client_queue_item;
        }
        else
        {
            /* Codes_SRS_QUEUE_07_022: [On success Queue_Enum_Next_Item shall return the next queue item from the previous call to Queue_Enum_Next_Item.] */
            queue_enum->prev_entry = queue_enum->current_entry;
            queue_enum->current_entry = queue_enum->current_entry->next;
            result = queue_enum->current_entry->client_queue_item;
        }
    }
    return result;
}

void Queue_Enum_Destroy(QUEUE_ENUM_HANDLE enum_handle)
{
    /* Codes_SRS_QUEUE_07_023: [If enum_handle is NULL Queue_Enum_Close shall do nothing.] */
    if (enum_handle != NULL)
    {
        /* Codes_SRS_QUEUE_07_024: [Queue_Enum_Close shall deallocate any information that has been allocated in Queue_Create_Enum.] */
        QUEUE_ENUM* queue_enum = (QUEUE_ENUM*)enum_handle;
        free(queue_enum);
    }
}

bool Queue_Is_Empty(QUEUE_HANDLE handle)
{
    bool result;
    if (handle == NULL)
    {
        /* Codes_SRS_QUEUE_07_013: [If handle is NULL Queue_Is_Empty shall return QUEUE_INVALID_ARG.] */
        LogError("Invalid argument: handle is NULL");
        result = true;
    }
    else
    {
        QUEUE_DATA* queue_data = (QUEUE_DATA*)handle;
        if (queue_data->list_entry == NULL)
        {
            result = true;
        }
        else
        {
            result = false;
        }
    }
    return result;
}

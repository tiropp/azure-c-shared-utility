# queue Requirements

## Overview

Queue object enables you to create a queue Item that can be enumerated.

Exposed API

```c
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
```

### Queue_Create

```c
QUEUE_HANDLE Queue_Create(QUEUE_REMOVE_ITEM_CALLBACK remove_callback)
```

**SRS_QUEUE_07_001: [**If an error is encountered `Queue_Create` shall return NULL.**]**

**SRS_QUEUE_07_002: [**On Success `Queue_Create` shall return a non-NULL handle that refers to a Queue.**]**

### Queue_Destroy

```c
void Queue_Destroy(QUEUE_HANDLE handle)
```

**SRS_QUEUE_07_003: [**If `handle` is NULL then `Queue_Destroy` shall do nothing.**]**

**SRS_QUEUE_07_004: [**`Queue_Destroy` shall only free memory allocated within this compilation unit.**]**

**SRS_QUEUE_07_005: [**If remove_callback is not NULL, `Queue_Destroy` shall call remove_callback with the item to be deleted.**]**

### Queue_Enqueue_Item

```c
QUEUE_RESULT Queue_Enqueue_Item(QUEUE_HANDLE handle, void* client_queue_item)
```

**SRS_QUEUE_07_006: [**If `handle` or `queue_item` are NULL `Queue_Enqueue_Item` shall return QUEUE_INVALID_ARG.**]**

**SRS_QUEUE_07_007: [**`Queue_Enqueue_Item` shall allocate a queue item and store the item into the queue.**]**

**SRS_QUEUE_07_008: [**On success `Queue_Enqueue_Item` shall return QUEUE_OK.**]**

**SRS_QUEUE_07_009: [**If any error is encountered `Queue_Enqueue_Item` shall return QUEUE_ERROR.**]**

### Queue_Get_Item

```c
const void* Queue_Get_Item(QUEUE_HANDLE handle)
```

**SRS_QUEUE_07_010: [**If `handle` is NULL `Queue_Get_Item` shall return NULL.**]**

**SRS_QUEUE_07_011: [**If the queue is empty, `Queue_Get_Item` shall return NULL.**]**

**SRS_QUEUE_07_012: [**`Queue_Get_Item` shall retrieved the front item from the queue and return the item.**]**

### Queue_Dequeue_Item

```c
QUEUE_RESULT Queue_Dequeue_Item(QUEUE_HANDLE handle)
```

**SRS_QUEUE_07_013: [**If `handle` is NULL `Queue_Dequeue_Item` shall return QUEUE_INVALID_ARG.**]**

**SRS_QUEUE_07_014: [**If the queue is empty, `Queue_Dequeue_Item` shall return QUEUE_EMPTY.**]**

**SRS_QUEUE_07_015: [**If `remove_callback` is not NULL, `Queue_Dequeue_Item` shall call `remove_callback`.**]**

**SRS_QUEUE_07_016: [**On success `Queue_Dequeue_Item` shall return QUEUE_OK.**]**

### Queue_Create_Enum

```c
QUEUE_ENUM_HANDLE Queue_Create_Enum(QUEUE_HANDLE handle)
```

**SRS_QUEUE_07_017: [**If `handle` is NULL `Queue_Create_Enum` shall return NULL.**]**

**SRS_QUEUE_07_018: [**`Queue_Create_Enum` shall allocate and initialize the data neccessary for enumeration of the queue.**]**

**SRS_QUEUE_07_019: [**On Success `Queue_Create_Enum` shall return a non-NULL QUEUE_ENUM_HANDLE.**]**

**SRS_QUEUE_07_026: [**If any error is encountered `Queue_Create_Enum` shall return NULL.**]**

### Queue_Enum_Dequeue_Item

```c
QUEUE_RESULT Queue_Enum_Dequeue_Item(QUEUE_ENUM_HANDLE enum_handle)
```

`Queue_Enum_Dequeue_Item` removes the last entry enumerated entry from the queue.

**SRS_QUEUE_07_030: [** If `enum_handle` is NULL Queue_Enum_Dequeue_Item shall return QUEUE_INVALID_ARG. **]**

**SRS_QUEUE_07_031: [** If the enum_handle has encountered the last item `Queue_Enum_Dequeue_Item` shall return QUEUE_EMPTY. **]**

**SRS_QUEUE_07_032: [** If `remove_callback` is not NULL, `Queue_Enum_Dequeue_Item` shall call `remove_callback` with current enumerated item. **]**

**SRS_QUEUE_07_033: [** If successful `Queue_Enum_Dequeue_Item` shall return QUEUE_OK. **]**

**SRS_QUEUE_07_034: [**If the queue referenced by handle is empty `Queue_Create_Enum` shall return QUEUE_EMPTY.**]**

### Queue_Enum_Next_Item

```c
CLIENT_QUEUE_ITEM* Queue_Enum_Next_Item(QUEUE_ENUM_HANDLE enum_handle)
```

`Queue_Enum_Next_Item` shall start at the front of the queue and return the next item on successive calls.

**SRS_QUEUE_07_020: [**If `enum_handle` is NULL `Queue_Enum_Next_Item` shall return NULL.**]**

**SRS_QUEUE_07_021: [**If the end of the queue is reached `Queue_Enum_Next_Item` shall return NULL.**]**

**SRS_QUEUE_07_022: [**On success `Queue_Enum_Next_Item` shall return the next queue item from the previous call to `Queue_Enum_Next_Item`.**]**


### Queue_Enum_Destroy

```c
void Queue_Enum_Destroy(QUEUE_ENUM_HANDLE enum_handle)
```

**SRS_QUEUE_07_023: [**If enum_handle is NULL `Queue_Enum_Destroy` shall do nothing.**]**

**SRS_QUEUE_07_024: [**`Queue_Enum_Destroy` shall deallocate any information that has been allocated in Queue_Create_Enum.**]**

### Queue_Is_Empty

```c
bool Queue_Is_Empty(QUEUE_HANDLE handle)
```

**SRS_IOTHUB_QUEUE_07_027: [**If `handle` is NULL Queue_Is_Empty shall return true.**]**

**SRS_IOTHUB_QUEUE_07_028: [**If the queue pointed to by handle is Empty `Queue_Is_Empty` shall return true.**]**

**SRS_IOTHUB_QUEUE_07_029: [**...Otherwise it shall return false.**]**
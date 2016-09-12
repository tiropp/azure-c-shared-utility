 // Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/wsio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/list.h"
#include "azure_c_shared_utility/optionhandler.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/crt_abstractions.h"

typedef enum IO_STATE_TAG
{
    IO_STATE_NOT_OPEN,
    IO_STATE_OPENING,
    IO_STATE_OPEN,
    IO_STATE_CLOSING,
    IO_STATE_ERROR
} IO_STATE;

typedef struct PENDING_SOCKET_IO_TAG
{
    unsigned char* bytes;
    size_t size;
    ON_SEND_COMPLETE on_send_complete;
    void* callback_context;
    LIST_HANDLE pending_io_list;
    bool is_partially_sent;
} PENDING_SOCKET_IO;

typedef struct WSIO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    void* on_bytes_received_context;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    void* on_io_open_complete_context;
    ON_IO_ERROR on_io_error;
    void* on_io_error_context;
    IO_STATE io_state;
    LIST_HANDLE pending_io_list;
    char* hostname;
    char* proxy_address;
    int proxy_port;
    XIO_HANDLE underlying_io;
    size_t received_byte_count;
    unsigned char* received_bytes;
} WSIO_INSTANCE;

static void indicate_error(WSIO_INSTANCE* wsio_instance)
{
    wsio_instance->io_state = IO_STATE_ERROR;
    if (wsio_instance->on_io_error != NULL)
    {
        wsio_instance->on_io_error(wsio_instance->on_io_error_context);
    }
}

static void indicate_open_complete(WSIO_INSTANCE* ws_io_instance, IO_OPEN_RESULT open_result)
{
    if (ws_io_instance->on_io_open_complete != NULL)
    {
        ws_io_instance->on_io_open_complete(ws_io_instance->on_io_open_complete_context, open_result);
    }
}

static int add_pending_io(WSIO_INSTANCE* ws_io_instance, const unsigned char* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    PENDING_SOCKET_IO* pending_socket_io = (PENDING_SOCKET_IO*)malloc(sizeof(PENDING_SOCKET_IO));
    if (pending_socket_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        pending_socket_io->bytes = (unsigned char*)malloc(size);
        if (pending_socket_io->bytes == NULL)
        {
            free(pending_socket_io);
            result = __LINE__;
        }
        else
        {
            pending_socket_io->is_partially_sent = false;
            pending_socket_io->size = size;
            pending_socket_io->on_send_complete = on_send_complete;
            pending_socket_io->callback_context = callback_context;
            pending_socket_io->pending_io_list = ws_io_instance->pending_io_list;
            (void)memcpy(pending_socket_io->bytes, buffer, size);

            if (list_add(ws_io_instance->pending_io_list, pending_socket_io) == NULL)
            {
                free(pending_socket_io->bytes);
                free(pending_socket_io);
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

static int remove_pending_io(WSIO_INSTANCE* wsio_instance, LIST_ITEM_HANDLE item_handle, PENDING_SOCKET_IO* pending_socket_io)
{
    int result;

    free(pending_socket_io->bytes);
    free(pending_socket_io);
    if (list_remove(wsio_instance->pending_io_list, item_handle) != 0)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
    }

    return result;
}

static void send_pending_ios(WSIO_INSTANCE* wsio_instance)
{
    LIST_ITEM_HANDLE first_pending_io;

    first_pending_io = list_get_head_item(wsio_instance->pending_io_list);

    if (first_pending_io != NULL)
    {
        PENDING_SOCKET_IO* pending_socket_io = (PENDING_SOCKET_IO*)list_item_get_value(first_pending_io);
        if (pending_socket_io == NULL)
        {
            indicate_error(wsio_instance);
        }
        else
        {
            bool is_partially_sent = pending_socket_io->is_partially_sent;
            size_t frame_length = 6;
            if (pending_socket_io->size > 125)
            {
                frame_length += 2;
            }
            if (pending_socket_io->size > 65535)
            {
                frame_length += 6;
            }

            frame_length += pending_socket_io->size;

            unsigned char* ws_buffer = (unsigned char*)malloc(frame_length);
            if (ws_buffer == NULL)
            {
                if (pending_socket_io->on_send_complete != NULL)
                {
                    pending_socket_io->on_send_complete(pending_socket_io->callback_context, IO_SEND_ERROR);
                }

                if (is_partially_sent)
                {
                    indicate_error(wsio_instance);
                }
                else
                {
                    if (list_get_head_item(wsio_instance->pending_io_list) != NULL)
                    {
                        /* continue ... */
                    }
                }

                if ((remove_pending_io(wsio_instance, first_pending_io, pending_socket_io) != 0) && !is_partially_sent)
                {
                    indicate_error(wsio_instance);
                }
            }
            else
            {
                /* fill in frame */
                size_t pos = 0;

                ws_buffer[0] = (1 << 0) +
                    (2 << 4);
                ws_buffer[1] = (1 << 0);
                if (pending_socket_io->size < 126)
                {
                    ws_buffer[1] |= (pending_socket_io->size << 1);
                    pos = 2;
                }
                else if (pending_socket_io->size < 65536)
                {
                    ws_buffer[1] |= (126 << 1);
                    ws_buffer[2] |= (pending_socket_io->size & 0xFF);
                    ws_buffer[3] |= (pending_socket_io->size >> 8);
                    pos = 4;
                }
                else
                {
                    ws_buffer[1] |= (127 << 1);
                    ws_buffer[2] |= ((uint64_t)pending_socket_io->size & 0xFF);
                    ws_buffer[3] |= ((uint64_t)pending_socket_io->size >> 8) & 0xFF;
                    ws_buffer[4] |= ((uint64_t)pending_socket_io->size >> 16) & 0xFF;
                    ws_buffer[5] |= ((uint64_t)pending_socket_io->size >> 24) & 0xFF;
                    ws_buffer[6] |= ((uint64_t)pending_socket_io->size >> 32) & 0xFF;
                    ws_buffer[7] |= ((uint64_t)pending_socket_io->size >> 40) & 0xFF;
                    ws_buffer[8] |= ((uint64_t)pending_socket_io->size >> 48) & 0xFF;
                    ws_buffer[9] |= ((uint64_t)pending_socket_io->size >> 56) & 0xFF;
                    pos = 10;
                }

                /* mask key */
                ws_buffer[pos++] = 0xFF;
                ws_buffer[pos++] = 0xFF;
                ws_buffer[pos++] = 0xFF;
                ws_buffer[pos++] = 0xFF;

                (void)memcpy(ws_buffer + pos, pending_socket_io->bytes, pending_socket_io->size);
                pos += pending_socket_io->size;

                if (xio_send(wsio_instance->underlying_io, ws_buffer, pos, pending_socket_io->on_send_complete, pending_socket_io->callback_context) != 0)
                {
                    indicate_error(wsio_instance);
                }
                else
                {
                    LogInfo("sent");
                    if (remove_pending_io(wsio_instance, first_pending_io, pending_socket_io) != 0)
                    {
                        indicate_error(wsio_instance);
                    }
                }

                free(ws_buffer);
            }
        }
    }
}

CONCRETE_IO_HANDLE wsio_create(void* io_create_parameters)
{
    WSIO_CONFIG* ws_io_config = io_create_parameters;
    WSIO_INSTANCE* result;

    if ((ws_io_config == NULL) ||
        (ws_io_config->underlying_io == NULL))
    {
        result = NULL;
    }
    else
    {
        result = (WSIO_INSTANCE*)malloc(sizeof(WSIO_INSTANCE));
        if (result != NULL)
        {
            size_t hostname_length;

            result->on_bytes_received = NULL;
            result->on_bytes_received_context = NULL;
            result->on_io_open_complete = NULL;
            result->on_io_open_complete_context = NULL;
            result->on_io_error = NULL;
            result->on_io_error_context = NULL;
            result->proxy_address = NULL;
            result->proxy_port = 0;
            result->received_bytes = NULL;
            result->received_byte_count = 0;
            result->underlying_io = ws_io_config->underlying_io;

            hostname_length = strlen(ws_io_config->hostname);
            result->hostname = malloc(hostname_length + 1);
            if (result->hostname == NULL)
            {
                free(result);
                result = NULL;
            }
            else
            {
                (void)memcpy(result->hostname, ws_io_config->hostname, hostname_length + 1);

                result->pending_io_list = list_create();
                if (result->pending_io_list == NULL)
                {
                    free(result->hostname);
                    free(result);
                    result = NULL;
                }
                else
                {
                    result->io_state = IO_STATE_NOT_OPEN;
                }
            }
        }
    }

    return result;
}

static void on_underlying_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)context;
    (void)context, open_result;
    const char upgrade_request_format[] = "GET /$iothub/websocket HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-length: 0\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: AMQPWSB10\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";

    char upgrade_request[2048];
    size_t len = sprintf(upgrade_request, upgrade_request_format, wsio_instance->hostname);

    if (xio_send(wsio_instance->underlying_io, upgrade_request, len, NULL, NULL) != 0)
    {
        LogError("Error sending upgrade request");
    }
}

static void on_underlying_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)context;

    (void)buffer, size;
    LogInfo("Received %zu bytes", size);

    unsigned char* new_received_bytes = (unsigned char*)realloc(wsio_instance->received_bytes, wsio_instance->received_byte_count + size);
    if (new_received_bytes == NULL)
    {
        /* error */
    }
    else
    {

        wsio_instance->received_bytes = new_received_bytes;
        (void)memcpy(wsio_instance->received_bytes, buffer, size);
        wsio_instance->received_byte_count += size;

        if (wsio_instance->io_state == IO_STATE_OPENING)
        {
            size_t pos = 0;
            size_t last_pos = 0;
            unsigned char done = 0;

            while (done == 0)
            {
                /* parse the Upgrade */
                while ((pos < wsio_instance->received_byte_count) &&
                    (wsio_instance->received_bytes[pos] != '\r'))
                {
                    pos++;
                }

                if (pos == wsio_instance->received_byte_count)
                {
                    break;
                }

                if (pos - last_pos == 0)
                {
                    pos++;

                    while ((pos < wsio_instance->received_byte_count) &&
                        (wsio_instance->received_bytes[pos] == '\n'))
                    {
                        pos++;
                    }

                    done = 1;
                }
                else
                {
                    pos++;

                    while ((pos < wsio_instance->received_byte_count) &&
                        (wsio_instance->received_bytes[pos] == '\n'))
                    {
                        pos++;
                    }

                    if (pos == wsio_instance->received_byte_count)
                    {
                        break;
                    }

                    last_pos = pos;
                }
            }

            if (done)
            {
                if (wsio_instance->received_byte_count - pos > 0)
                {
                    (void)memmove(wsio_instance->received_bytes, wsio_instance->received_bytes + pos, wsio_instance->received_byte_count - pos);
                }

                wsio_instance->received_byte_count -= pos;

                /* parsed the upgrade response ... we assume */
                LogInfo("Got WS upgrade response");
                wsio_instance->io_state = IO_STATE_OPEN;
                indicate_open_complete(wsio_instance, IO_OPEN_OK);
            }
        }

        if (wsio_instance->io_state == IO_STATE_OPEN)
        {
            /* parse each frame */
            /* check frame type */
            uint64_t needed_bytes = 6;
            if (wsio_instance->received_byte_count >= needed_bytes)
            {
                uint64_t payload_length = wsio_instance->received_bytes[1] & 0x7F;
                if (payload_length == 126)
                {
                    needed_bytes += 2;
                    if (wsio_instance->received_byte_count >= needed_bytes)
                    {
                        payload_length = wsio_instance->received_bytes[2];
                        payload_length |= (uint16_t)wsio_instance->received_bytes[3] << 8;
                    }
                }
                else if (payload_length == 127)
                {
                    needed_bytes += 8;
                    if (wsio_instance->received_byte_count >= needed_bytes)
                    {
                        payload_length = wsio_instance->received_bytes[2];
                        payload_length |= (uint64_t)wsio_instance->received_bytes[3] << 8;
                        payload_length |= (uint64_t)wsio_instance->received_bytes[4] << 16;
                        payload_length |= (uint64_t)wsio_instance->received_bytes[5] << 24;
                        payload_length |= (uint64_t)wsio_instance->received_bytes[6] << 32;
                        payload_length |= (uint64_t)wsio_instance->received_bytes[7] << 40;
                        payload_length |= (uint64_t)wsio_instance->received_bytes[8] << 48;
                        payload_length |= (uint64_t)wsio_instance->received_bytes[9] << 56;
                    }
                }

                needed_bytes += payload_length;
                if (wsio_instance->received_byte_count >= needed_bytes)
                {
                    unsigned char opcode = wsio_instance->received_bytes[0] >> 4;
                    if (opcode == 2)
                    {
                        wsio_instance->on_bytes_received(wsio_instance->on_bytes_received_context, wsio_instance->received_bytes + needed_bytes - payload_length, (size_t)payload_length);
                    }
                }
            }
        }
    }
}

static void on_underlying_io_error(void* context)
{
    (void)context;
}

int wsio_open(CONCRETE_IO_HANDLE ws_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result = 0;

    if (ws_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)ws_io;

        if (wsio_instance->io_state != IO_STATE_NOT_OPEN)
        {
            result = __LINE__;
        }
        else
        {
            wsio_instance->on_bytes_received = on_bytes_received;
            wsio_instance->on_bytes_received_context = on_bytes_received_context;
            wsio_instance->on_io_open_complete = on_io_open_complete;
            wsio_instance->on_io_open_complete_context = on_io_open_complete_context;
            wsio_instance->on_io_error = on_io_error;
            wsio_instance->on_io_error_context = on_io_error_context;

            wsio_instance->io_state = IO_STATE_OPENING;

            /* connect here */
            if (xio_open(wsio_instance->underlying_io, on_underlying_io_open_complete, wsio_instance, on_underlying_io_bytes_received, wsio_instance, on_underlying_io_error, wsio_instance) != 0)
            {
                /* Error */
                wsio_instance->io_state = IO_STATE_NOT_OPEN;
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
        }
    }
    
    return result;
}

int wsio_close(CONCRETE_IO_HANDLE ws_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* on_io_close_complete_context)
{
    int result = 0;

    if (ws_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)ws_io;

        if (wsio_instance->io_state == IO_STATE_NOT_OPEN)
        {
            result = __LINE__;
        }
        else
        {
            if (wsio_instance->io_state == IO_STATE_OPENING)
            {
                indicate_open_complete(wsio_instance, IO_OPEN_CANCELLED);
            }
            else
            {
                /* cancel all pending IOs */
                LIST_ITEM_HANDLE first_pending_io;

                while ((first_pending_io = list_get_head_item(wsio_instance->pending_io_list)) != NULL)
                {
                    PENDING_SOCKET_IO* pending_socket_io = (PENDING_SOCKET_IO*)list_item_get_value(first_pending_io);

                    if (pending_socket_io != NULL)
                    {
                        if (pending_socket_io->on_send_complete != NULL)
                        {
                            pending_socket_io->on_send_complete(pending_socket_io->callback_context, IO_SEND_CANCELLED);
                        }

                        if (pending_socket_io != NULL)
                        {
                            free(pending_socket_io->bytes);
                            free(pending_socket_io);
                        }
                    }

                    (void)list_remove(wsio_instance->pending_io_list, first_pending_io);
                }
            }

            xio_close(wsio_instance->underlying_io, NULL, NULL);
            wsio_instance->io_state = IO_STATE_NOT_OPEN;

            if (on_io_close_complete != NULL)
            {
                on_io_close_complete(on_io_close_complete_context);
            }

            result = 0;
        }
    }

    return result;
}

void wsio_destroy(CONCRETE_IO_HANDLE ws_io)
{
    if (ws_io != NULL)
    {
        WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)ws_io;

        (void)wsio_close(wsio_instance, NULL, NULL);

        list_destroy(wsio_instance->pending_io_list);

        if (wsio_instance->hostname != NULL)
        {
            free(wsio_instance->hostname);
        }
        if (wsio_instance->received_bytes != NULL)
        {
            free(wsio_instance->received_bytes);
        }

        free(ws_io);
    }
}

int wsio_send(CONCRETE_IO_HANDLE ws_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;

    if ((ws_io == NULL) ||
        (buffer == NULL) ||
        (size == 0))
    {
        result = __LINE__;
    }
    else
    {
        WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)ws_io;

        if (wsio_instance->io_state != IO_STATE_OPEN)
        {
            result = __LINE__;
        }
        else
        {
            if (add_pending_io(wsio_instance, buffer, size, on_send_complete, callback_context) != 0)
            {
                result = __LINE__;
            }
            else
            {
                /* I guess send here */
                send_pending_ios(wsio_instance);

                result = 0;
            }
        }
    }

    return result;
}

void wsio_dowork(CONCRETE_IO_HANDLE ws_io)
{
    if (ws_io != NULL)
    {
        WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)ws_io;

        if ((wsio_instance->io_state == IO_STATE_OPEN) ||
            (wsio_instance->io_state == IO_STATE_OPENING))
        {
            xio_dowork(wsio_instance->underlying_io);
        }
    }
}

int wsio_setoption(CONCRETE_IO_HANDLE ws_io, const char* optionName, const void* value)
{
    int result;
    if (
        (ws_io == NULL) ||
        (optionName == NULL) ||
        (value == NULL)
        )
    {
        result = __LINE__;
        LogError("invalid parameter (NULL) passed to HTTPAPI_SetOption");
    }
    else
    {
        WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)ws_io;
        if (strcmp(OPTION_PROXY_ADDRESS, optionName) == 0)
        {
            if (wsio_instance->proxy_address != NULL)
            {
                free(wsio_instance->proxy_address);
            }
            result = mallocAndStrcpy_s(&wsio_instance->proxy_address, (const char*)value);
        }
        else if (strcmp(OPTION_PROXY_PORT, optionName) == 0)
        {
            result = *(int*)value;
        }
        else if (strcmp(OPTION_HTTP_PROXY, optionName) == 0)
        {
            HTTP_PROXY_OPTIONS* proxy_data = (HTTP_PROXY_OPTIONS*)value;
            if (proxy_data->host_address == NULL || (proxy_data->username != NULL && proxy_data->password == NULL))
            {
                result = __LINE__;
            }
            else
            {
                wsio_instance->proxy_port = proxy_data->port;
                if (proxy_data->username != NULL)
                {
                    size_t length = strlen(proxy_data->host_address)+strlen(proxy_data->username)+strlen(proxy_data->password)+3+5;
                    wsio_instance->proxy_address = (char*)malloc(length+1);
                    if (wsio_instance->proxy_address == NULL)
                    {
                        result = __LINE__;
                    }
                    else
                    {
                        if (sprintf(wsio_instance->proxy_address, "%s:%s@%s:%d", proxy_data->username, proxy_data->password, proxy_data->host_address, wsio_instance->proxy_port) <= 0)
                        {
                            result = __LINE__;
                            free(wsio_instance->proxy_address);
                        }
                        else
                        {
                            result = 0;
                        }
                    }
                }
                else
                {
                    size_t length = strlen(proxy_data->host_address)+6+1;
                    wsio_instance->proxy_address = (char*)malloc(length+1);
                    if (wsio_instance->proxy_address == NULL)
                    {
                        result = __LINE__;
                    }
                    else
                    {
                        if (sprintf(wsio_instance->proxy_address, "%s:%d", proxy_data->host_address, wsio_instance->proxy_port) <= 0)
                        {
                            result = __LINE__;
                            free(wsio_instance->proxy_address);
                        }
                        else
                        {
                            result = 0;
                        }
                    }
                }
            }
        }
        else
        {
            result = __LINE__;
        }
    }
    return result;
}

/*this function will clone an option given by name and value*/
void* wsio_CloneOption(const char* name, const void* value)
{
    void* result;
    if (
        (name == NULL) || (value == NULL)
       )
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
        result = NULL;
    }
    else if (strcmp(OPTION_PROXY_ADDRESS, name) == 0)
    {
        if (mallocAndStrcpy_s((char**)&result, (const char*)value) != 0)
        {
            LogError("unable to mallocAndStrcpy_s proxy_address value");
            result = NULL;
        }
    }
    else if (strcmp(OPTION_PROXY_PORT, name) == 0)
    {
        int* temp = malloc(sizeof(int));
        if (temp == NULL)
        {
            LogError("unable to allocate port number");
            result = NULL;
        }
        else
        {
            *temp = *(const int*)value;
            result = temp;
        }
    }
    else
    {
        result = NULL;
    }
    return result;
}

/*this function destroys an option previously created*/
void wsio_DestroyOption(const char* name, const void* value)
{
    if (
        (name == NULL) || (value == NULL)
       )
    {
        LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
    }
    else if (strcmp(name, OPTION_HTTP_PROXY) == 0)
    {
        HTTP_PROXY_OPTIONS* proxy_data = (HTTP_PROXY_OPTIONS*)value;
        free((char*)proxy_data->host_address);
        if (proxy_data->username)
        {
            free((char*)proxy_data->username);
        }
        if (proxy_data->password)
        {
            free((char*)proxy_data->password);
        }
        free(proxy_data);
    }
    else if ((strcmp(name, OPTION_PROXY_ADDRESS) == 0) ||
        (strcmp(name, OPTION_PROXY_PORT) == 0))
    {
        free((void*)value);
    }
}

OPTIONHANDLER_HANDLE wsio_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
    OPTIONHANDLER_HANDLE result;
    if (handle == NULL)
    {
        LogError(" parameter CONCRETE_IO_HANDLE handle=%p", handle);
        result = NULL;
    }
    else
    {
        /*Codes_SRS_WSIO_02_002: [ wsio_retrieveoptions shall produce an empty OPTIOHANDLER_HANDLE. ]*/
        result = OptionHandler_Create(wsio_CloneOption, wsio_DestroyOption, wsio_setoption);
        if (result == NULL)
        {
            LogError("unable to OptionHandler_Create");
            /*return as is*/
        }
        else
        {
            WSIO_INSTANCE* wsio_instance = (WSIO_INSTANCE*)handle;
            if (
                (wsio_instance->proxy_address != NULL) && 
                (OptionHandler_AddOption(result, OPTION_PROXY_ADDRESS, wsio_instance->proxy_address) != 0)
               )
            {
                LogError("unable to save proxy_address option");
                OptionHandler_Destroy(result);
                result = NULL;
            }
            else if ( 
                (wsio_instance->proxy_port != 0) && 
                (OptionHandler_AddOption(result, OPTION_PROXY_PORT, &wsio_instance->proxy_port) != 0)
                )
            {
                LogError("unable to save proxy_port option");
                OptionHandler_Destroy(result);
                result = NULL;
            }
        }
    }
    return result;
}


static const IO_INTERFACE_DESCRIPTION ws_io_interface_description =
{
    wsio_retrieveoptions,
    wsio_create,
    wsio_destroy,
    wsio_open,
    wsio_close,
    wsio_send,
    wsio_dowork,
    wsio_setoption
};

const IO_INTERFACE_DESCRIPTION* wsio_get_interface_description(void)
{
    return &ws_io_interface_description;
}


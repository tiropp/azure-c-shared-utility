// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TLSIO_ARDUINO_H
#define TLSIO_ARDUINO_H

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#else
#include <stddef.h>
#endif /* __cplusplus */

#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/umock_c_prod.h"

#define UNABLE_TO_COMPLETE -2
#define MBED_RECEIVE_BYTES_VALUE    128


MOCKABLE_FUNCTION(, CONCRETE_IO_HANDLE, tlsio_arduino_create, void*, io_create_parameters);
MOCKABLE_FUNCTION(, void, tlsio_arduino_destroy, CONCRETE_IO_HANDLE, tls_io);
MOCKABLE_FUNCTION(, int, tlsio_arduino_open, CONCRETE_IO_HANDLE, tls_io, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, int, tlsio_arduino_close, CONCRETE_IO_HANDLE, tls_io, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, tlsio_arduino_send, CONCRETE_IO_HANDLE, tls_io, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, tlsio_arduino_dowork, CONCRETE_IO_HANDLE, tls_io);
MOCKABLE_FUNCTION(, int, tlsio_arduino_setoption, CONCRETE_IO_HANDLE, tls_io, const char*, optionName, const void*, value);
MOCKABLE_FUNCTION(, OPTIONHANDLER_HANDLE, tlsio_arduino_retrieveoptions, CONCRETE_IO_HANDLE, tls_io);

MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, tlsio_arduino_get_interface_description);

#ifdef __cplusplus
}
#endif /* __cplusplus */

class ArduinoTLS
{
private:
    typedef enum IO_STATE_TAG
    {
        IO_STATE_CLOSED,
        IO_STATE_OPENING,
        IO_STATE_OPEN,
        IO_STATE_CLOSING,
        IO_STATE_ERROR
    } IO_STATE;

private:
    Client* _sslClient;
    ON_BYTES_RECEIVED _on_bytes_received;
    ON_IO_ERROR _on_io_error;
    void* _on_bytes_received_context;
    void* _on_io_error_context;
    IPAddress _remote_addr;
    int _port;
    IO_STATE _io_state;

public:
    ArduinoTLS();
    ~ArduinoTLS();

    bool Create(void* io_create_parameters);
    int Open(
        ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
        ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
        ON_IO_ERROR on_io_error, void* on_io_error_context);
    int Close();
    int Send(const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context);
    void Dowork(void);

private:
    void IndicateError(void);

};

#endif /* TLSIO_ARDUINO_H */

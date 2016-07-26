// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <Client.h>
#include <Print.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "tlsio_arduino.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/threadapi.h"

#ifdef ARDUINO_ARCH_ESP8266
#include "ESP8266WiFi.h"
#include "WiFiClientSecure.h"
#elif ARDUINO_SAMD_FEATHER_M0
#include "Adafruit_WINC1500.h"
#include "Adafruit_WINC1500Client.h"
#include "Adafruit_WINC1500SSLClient.h"
#else
#include "WiFi101.h"
#include "WiFiSSLClient.h"
#endif

#define IndicateError() { if (_on_io_error != NULL) _on_io_error(_on_io_error_context); }

ArduinoTLS::ArduinoTLS()
{
#ifdef ARDUINO_ARCH_ESP8266
    _sslClient = (Client*)new WiFiClientSecure(); // for ESP8266
#elif ARDUINO_SAMD_FEATHER_M0
    _sslClient = (Client*)new Adafruit_WINC1500SSLClient(); // for Adafruit WINC1500
#else
    _sslClient = (Client*)new WiFiSSLClient();
#endif

    if (_sslClient == NULL)
    {
        LogError("Invalid SSL client");
    }
    else
    {
        _sslClient->setTimeout(10000);
    }

    _port = 0;
    _on_bytes_received = NULL;
    _on_io_error = NULL;
    _on_bytes_received_context = NULL;
    _on_io_error_context = NULL;
    _io_state = IO_STATE_CLOSED;
}

bool ArduinoTLS::Create(void* io_create_parameters)
{
    bool result = false;
    if (io_create_parameters == NULL)
    {
        LogError("Invalid TLS parameters");
    }
    else if (_sslClient != NULL)
    {
        TLSIO_CONFIG* tlsio_config = (TLSIO_CONFIG*)io_create_parameters;

        if (WiFi.hostByName(tlsio_config->hostname, _remote_addr))
        {
            LogInfo("WiFi convert %s in %d.%d.%d.%d", tlsio_config->hostname, _remote_addr[0], _remote_addr[1], _remote_addr[2], _remote_addr[3]);
            _port = tlsio_config->port;
            result = true;
        }
        else
        {
            LogError("Host %s not found", tlsio_config->hostname);
        }
    }
    return result;
}

ArduinoTLS::~ArduinoTLS()
{
    if (_sslClient != NULL)
    {
        delete(_sslClient);
        _sslClient = NULL;
    }
}

int ArduinoTLS::Open(
    ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
    ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
    ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result = __LINE__;

    if (_sslClient != NULL)
    {
        if (_sslClient->connected())
        {
            LogError("No HTTPS clients available");
        }

        if (_sslClient->connect(_remote_addr, _port))
        {
            while (!_sslClient->connected());
            _on_bytes_received = on_bytes_received;
            _on_bytes_received_context = on_bytes_received_context;

            _on_io_error = on_io_error;
            _on_io_error_context = on_io_error_context;

            _io_state = IO_STATE_OPEN;

            if (on_io_open_complete != NULL)
            {
                on_io_open_complete(on_io_open_complete_context, IO_OPEN_OK);
            }

            result = 0;
        }
    }
    return result;
}

int ArduinoTLS::Close()
{
    int result = __LINE__;

    if (_sslClient != NULL)
    {
        _sslClient->stop();
        result = 0;
    }
    return result;
}

int ArduinoTLS::Send(const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result = __LINE__;

    if ((_sslClient != NULL) &&
        (buffer != NULL) &&
        (size != 0) &&
        (_io_state == IO_STATE_OPEN))
    {
        size_t send_result = 0;
        size_t send_size = size;
        const uint8_t* runBuffer = (const uint8_t *)buffer;
        while (1)
        {
            send_result = _sslClient->write(runBuffer, send_size);
            if (send_result == send_size) /* Transmit it all. */
            {
                result = 0;
                if (on_send_complete != NULL)
                {
                    on_send_complete(callback_context, IO_SEND_OK);
                }
                break;
            }
            else if (send_result == 0) /* Don't transmit anything! Fail. */
            {
                result = __LINE__;
                break;
            }
            else /* Still have buffer to transmit. */
            {
                runBuffer += send_result;
                send_size -= send_result;
                ThreadAPI_Sleep(1);
            }
        } 
    }

    return result;
}


void ArduinoTLS::Dowork(void)
{
    uint8_t RecvBuffer[MBED_RECEIVE_BYTES_VALUE];

    if (_sslClient != NULL)
    {
        if (_io_state == IO_STATE_OPEN)
        {
            int received = 1;
            while (received > 0)
            {
                received = _sslClient->read((uint8_t*)RecvBuffer, MBED_RECEIVE_BYTES_VALUE);
                if (received > 0)
                {
                    if (_on_bytes_received != NULL)
                    {
                        // explictly ignoring here the result of the callback
                        (void)_on_bytes_received(_on_bytes_received_context, RecvBuffer, received);
                    }
                }
            }
        }
    }
}

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#else
#include <stddef.h>
#endif /* __cplusplus */

static const IO_INTERFACE_DESCRIPTION tlsio_handle_interface_description =
{
    tlsio_arduino_retrieveoptions,
    tlsio_arduino_create,
    tlsio_arduino_destroy,
    tlsio_arduino_open,
    tlsio_arduino_close,
    tlsio_arduino_send,
    tlsio_arduino_dowork,
    tlsio_arduino_setoption
};

CONCRETE_IO_HANDLE tlsio_arduino_create(void* io_create_parameters)
{
    ArduinoTLS* tlsio_instance = new ArduinoTLS();

    if (tlsio_instance == NULL)
    {
        LogError("Create TLSIO instance failed");
    }
    else
    {
        if (!tlsio_instance->Create(io_create_parameters))
        {
            LogError("Create TLSIO failed");
            delete tlsio_instance;
            tlsio_instance = NULL;
        }
    }
    return (CONCRETE_IO_HANDLE)tlsio_instance;
}

void tlsio_arduino_destroy(CONCRETE_IO_HANDLE tlsio_handle)
{
    if (tlsio_handle == NULL)
        return;

    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;
    delete tlsio_instance;
    tlsio_instance = NULL;
}

int tlsio_arduino_open(
    CONCRETE_IO_HANDLE tlsio_handle, 
    ON_IO_OPEN_COMPLETE on_io_open_complete, 
    void* on_io_open_complete_context, 
    ON_BYTES_RECEIVED on_bytes_received, 
    void* on_bytes_received_context, 
    ON_IO_ERROR on_io_error, 
    void* on_io_error_context)
{
    if (tlsio_handle == NULL)
        return __LINE__;

    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;
    return tlsio_instance->Open(on_io_open_complete, on_io_open_complete_context, on_bytes_received, on_bytes_received_context, on_io_error, on_io_error_context);
}

int tlsio_arduino_close(CONCRETE_IO_HANDLE tlsio_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    if (tlsio_handle == NULL)
        return __LINE__;

    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;
    return tlsio_instance->Close();
}

int tlsio_arduino_send(CONCRETE_IO_HANDLE tlsio_handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    if (tlsio_handle == NULL)
        return __LINE__;

    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;
    return tlsio_instance->Send(buffer, size, on_send_complete, callback_context);
}

void tlsio_arduino_dowork(CONCRETE_IO_HANDLE tlsio_handle)
{
    if (tlsio_handle == NULL)
        return ;

    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;
    tlsio_instance->Dowork();
}

/*this function will clone an option given by name and value*/
static void* tlsio_arduino_CloneOption(const char* name, const void* value)
{
    (void)(name, value);
    return NULL;
}

/*this function destroys an option previously created*/
static void tlsio_arduino_DestroyOption(const char* name, const void* value)
{
    (void)(name, value);
}

int tlsio_arduino_setoption(CONCRETE_IO_HANDLE tlsio_handle, const char* optionName, const void* value)
{
    /* Not implementing any options */
    return __LINE__;
}

OPTIONHANDLER_HANDLE tlsio_arduino_retrieveoptions(CONCRETE_IO_HANDLE tlsio_handle)
{
    if (tlsio_handle == NULL)
        return NULL;
    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;

    OPTIONHANDLER_HANDLE result;
    (void)tlsio_instance;
    result = OptionHandler_Create(tlsio_arduino_CloneOption, tlsio_arduino_DestroyOption, tlsio_arduino_setoption);
    if (result == NULL)
    {
        LogError("unable to OptionHandler_Create");
        /*return as is*/
    }
    else
    {
        /*insert here work to add the options to "result" handle*/
    }
    return result;
}

const IO_INTERFACE_DESCRIPTION* tlsio_arduino_get_interface_description(void)
{
    return &tlsio_handle_interface_description;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
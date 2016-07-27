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
#include <cstddef>
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

#define MAX_TLS_OPENING_RETRY  10
#define MAX_TLS_CLOSING_RETRY  10
#define RECEIVE_BUFFER_SIZE    128

#define IndicateError() do { if (_on_io_error != NULL) _on_io_error(_on_io_error_context); } while(0)

typedef enum IO_STATE_TAG
{
	IO_STATE_CLOSED,
	IO_STATE_OPENING,
	IO_STATE_OPEN,
	IO_STATE_CLOSING,
	IO_STATE_ERROR
} IO_STATE;

typedef struct ArduinoTLS_tag
{
	Client* sslClient;

	ON_IO_OPEN_COMPLETE on_io_open_complete;
	void* on_io_open_complete_context;

	ON_BYTES_RECEIVED on_bytes_received;
	void* on_bytes_received_context;

	ON_IO_ERROR on_io_error;
	void* on_io_error_context;

	ON_IO_CLOSE_COMPLETE on_io_close_complete;
	void* on_io_close_complete_context;

	IPAddress remote_addr;
	int port;
	IO_STATE io_state;
	int countTry;
} ArduinoTLS;


MOCKABLE_FUNCTION(, CONCRETE_IO_HANDLE, tlsio_arduino_create, void*, io_create_parameters);
MOCKABLE_FUNCTION(, void, tlsio_arduino_destroy, CONCRETE_IO_HANDLE, tls_io);
MOCKABLE_FUNCTION(, int, tlsio_arduino_open, CONCRETE_IO_HANDLE, tls_io, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, int, tlsio_arduino_close, CONCRETE_IO_HANDLE, tls_io, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, tlsio_arduino_send, CONCRETE_IO_HANDLE, tls_io, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, tlsio_arduino_dowork, CONCRETE_IO_HANDLE, tls_io);
MOCKABLE_FUNCTION(, int, tlsio_arduino_setoption, CONCRETE_IO_HANDLE, tls_io, const char*, optionName, const void*, value);
MOCKABLE_FUNCTION(, OPTIONHANDLER_HANDLE, tlsio_arduino_retrieveoptions, CONCRETE_IO_HANDLE, tls_io);

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
	ArduinoTLS* tlsio_instance;
	if (io_create_parameters == NULL)
	{
		LogError("Invalid TLS parameters");
		tlsio_instance = NULL;
	}
	else
	{
		tlsio_instance = (ArduinoTLS*)malloc(sizeof(ArduinoTLS));
		if (tlsio_instance == NULL)
		{
			LogError("Create TLS instance failed, there is not enough memory.");
		}
		else
		{
#ifdef ARDUINO_ARCH_ESP8266
			tlsio_instance->sslClient = new WiFiClientSecure(); // for ESP8266
#elif ARDUINO_SAMD_FEATHER_M0
			tlsio_instance->sslClient = new Adafruit_WINC1500SSLClient(); // for Adafruit WINC1500
#else
			tlsio_instance->sslClient = new WiFiSSLClient();
#endif

			tlsio_instance->sslClient->setTimeout(10000);

			tlsio_instance->on_io_open_complete = NULL;
			tlsio_instance->on_io_open_complete_context = NULL;
			tlsio_instance->on_bytes_received = NULL;
			tlsio_instance->on_bytes_received_context = NULL;
			tlsio_instance->on_io_error = NULL;
			tlsio_instance->on_io_error_context = NULL;
			tlsio_instance->on_io_close_complete = NULL;
			tlsio_instance->on_io_close_complete_context = NULL;
			tlsio_instance->io_state = IO_STATE_CLOSED;

			TLSIO_CONFIG* tlsio_config = (TLSIO_CONFIG*)io_create_parameters;

			if (WiFi.hostByName(tlsio_config->hostname, tlsio_instance->remote_addr))
			{
				LogInfo("WiFi converted %s in %d.%d.%d.%d", tlsio_config->hostname, tlsio_instance->remote_addr[0], tlsio_instance->remote_addr[1], tlsio_instance->remote_addr[2], tlsio_instance->remote_addr[3]);
				tlsio_instance->port = tlsio_config->port;
			}
			else
			{
				LogError("Host %s not found", tlsio_config->hostname);
				free(tlsio_instance);
				tlsio_instance = NULL;
			}
		}
	}
	return (CONCRETE_IO_HANDLE)tlsio_instance;
}

void tlsio_arduino_destroy(CONCRETE_IO_HANDLE tlsio_handle)
{
    if (tlsio_handle == NULL)
        return;

    ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;

	delete tlsio_instance->sslClient;
    free(tlsio_instance);
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

	int result;
	ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;

	tlsio_instance->on_io_open_complete = on_io_open_complete;
	tlsio_instance->on_io_open_complete_context = on_io_open_complete_context;

	tlsio_instance->on_bytes_received = on_bytes_received;
	tlsio_instance->on_bytes_received_context = on_bytes_received_context;

	tlsio_instance->on_io_error = on_io_error;
	tlsio_instance->on_io_error_context = on_io_error_context;

	if (tlsio_instance->sslClient->connected())
	{
		LogError("No TLS clients available");
		tlsio_instance->io_state = IO_STATE_ERROR;
		result = __LINE__;
	}
	else if (tlsio_instance->sslClient->connect(tlsio_instance->remote_addr, tlsio_instance->port))
	{
		tlsio_instance->io_state = IO_STATE_OPENING;
		tlsio_instance->countTry = MAX_TLS_OPENING_RETRY;
		result = 0;
	}
	else
	{
		LogError("TLS connect failed");
		tlsio_instance->io_state = IO_STATE_ERROR;
		result = __LINE__;
	}

	if (result != 0)
	{
		if (tlsio_instance->on_io_open_complete != NULL)
		{
			(void)tlsio_instance->on_io_open_complete(tlsio_instance->on_io_open_complete_context, IO_OPEN_ERROR);
		}
		if (tlsio_instance->on_io_error != NULL)
		{
			(void)tlsio_instance->on_io_error(tlsio_instance->on_io_error_context);
		}
	}
	else
	{
		tlsio_arduino_dowork(tlsio_handle);
	}

	return result;
}

int tlsio_arduino_close(CONCRETE_IO_HANDLE tlsio_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    if (tlsio_handle == NULL)
        return __LINE__;

	int result;
	ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;

	tlsio_instance->on_io_close_complete = on_io_close_complete;
	tlsio_instance->on_io_close_complete_context = callback_context;

	if ((tlsio_instance->io_state == IO_STATE_CLOSED) || (tlsio_instance->io_state == IO_STATE_ERROR))
	{
		tlsio_instance->io_state = IO_STATE_ERROR;
		result = __LINE__;
		if (tlsio_instance->on_io_close_complete != NULL)
		{
			(void)tlsio_instance->on_io_close_complete(tlsio_instance->on_io_close_complete_context);
		}
		if (tlsio_instance->on_io_error != NULL)
		{
			(void)tlsio_instance->on_io_error(tlsio_instance->on_io_error_context);
		}
	}
	else
	{
		tlsio_instance->sslClient->stop();
		tlsio_instance->io_state = IO_STATE_CLOSING;
		tlsio_instance->countTry = MAX_TLS_CLOSING_RETRY;
		result = 0;
		tlsio_arduino_dowork(tlsio_handle);
	}
	return result;
}

int tlsio_arduino_send(CONCRETE_IO_HANDLE tlsio_handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    if ((tlsio_handle == NULL) || (buffer == NULL))
        return __LINE__;

	int result;
	ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;

	if (tlsio_instance->io_state != IO_STATE_OPEN)
	{
		LogError("TLS is not ready to send data");
	}
	else
	{
		size_t send_result;
		size_t send_size = size;
		const uint8_t* runBuffer = (const uint8_t *)buffer;
		while (send_size > 0)
		{
			send_result = tlsio_instance->sslClient->write(runBuffer, send_size);

			if (send_result == 0) /* Didn't transmit anything! Failed. */
			{
				LogError("TLS failed sending data");
				result = __LINE__;
				if (on_send_complete != NULL)
				{
					on_send_complete(callback_context, IO_SEND_ERROR);
				}
				send_size = 0;
			}
			else if (send_result >= send_size) /* Transmit it all. */
			{
				result = 0;
				if (on_send_complete != NULL)
				{
					on_send_complete(callback_context, IO_SEND_OK);
				}
				send_size = 0;
			}
			else /* Still have buffer to transmit. */
			{
				runBuffer += send_result;
				send_size -= send_result;
			}
		}
	}

	return result;
}

void tlsio_arduino_dowork(CONCRETE_IO_HANDLE tlsio_handle)
{
    if (tlsio_handle == NULL)
        return ;

	int received;
	ArduinoTLS* tlsio_instance = (ArduinoTLS*)tlsio_handle;
	uint8_t RecvBuffer[RECEIVE_BUFFER_SIZE];

	switch (tlsio_instance->io_state)
	{
	case IO_STATE_OPENING:
		if (tlsio_instance->sslClient->connected())
		{
			tlsio_instance->io_state = IO_STATE_OPEN;
			if (tlsio_instance->on_io_open_complete != NULL)
			{
				(void)tlsio_instance->on_io_open_complete(tlsio_instance->on_io_open_complete_context, IO_OPEN_OK);
			}
		}
		else if ((tlsio_instance->countTry--) <= 0)
		{
			tlsio_instance->io_state = IO_STATE_ERROR;
			LogError("Timeout for TLS connect");
			if (tlsio_instance->on_io_open_complete != NULL)
			{
				(void)tlsio_instance->on_io_open_complete(tlsio_instance->on_io_open_complete_context, IO_OPEN_CANCELLED);
			}
			if (tlsio_instance->on_io_error != NULL)
			{
				(void)tlsio_instance->on_io_error(tlsio_instance->on_io_error_context);
			}
		}
		break;
	case IO_STATE_OPEN:
		received = tlsio_instance->sslClient->read((uint8_t*)RecvBuffer, RECEIVE_BUFFER_SIZE);
		if (received > 0)
		{
			if (tlsio_instance->on_bytes_received != NULL)
			{
				// explictly ignoring here the result of the callback
				(void)tlsio_instance->on_bytes_received(tlsio_instance->on_bytes_received_context, RecvBuffer, received);
			}
		}
		break;
	case IO_STATE_CLOSING:
		if (!tlsio_instance->sslClient->connected())
		{
			tlsio_instance->io_state = IO_STATE_CLOSED;
			if (tlsio_instance->on_io_close_complete != NULL)
			{
				(void)tlsio_instance->on_io_close_complete(tlsio_instance->on_io_close_complete_context);
			}
		}
		else if ((tlsio_instance->countTry--) <= 0)
		{
			tlsio_instance->io_state = IO_STATE_ERROR;
			LogError("Timeout for close TLS");
			if (tlsio_instance->on_io_error != NULL)
			{
				(void)tlsio_instance->on_io_error(tlsio_instance->on_io_error_context);
			}

		}
		break;
	case IO_STATE_CLOSED:
	case IO_STATE_ERROR:
	default:
		break;
	}
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
    return 0;
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
        LogError("unable to create OptionHandler");
        /*return as is*/
    }
    else
    {
        /*insert here work to add the options to "result" handle*/
    }
    return result;
}


extern "C" {

const IO_INTERFACE_DESCRIPTION* tlsio_arduino_get_interface_description(void)
{
    return &tlsio_handle_interface_description;
}

}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdio.h"
#include "azure_c_shared_utility\xio.h"
#include "azure_c_shared_utility\wsio.h"
#include "azure_c_shared_utility\tlsio.h"
#include "azure_c_shared_utility\platform.h"

static void on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    (void)context, open_result;
    (void)printf("Open complete called\r\n");

    XIO_HANDLE wsio = (XIO_HANDLE)context;
    xio_send(wsio, "Test", 4, NULL, NULL);
}

static void on_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    (void)context, buffer, size;
}

static void on_io_error(void* context)
{
    (void)context;
}


int main(int argc, void** argv)
{
    XIO_HANDLE wsio;
    XIO_HANDLE tlsio;
    WSIO_CONFIG wsio_config;
    int result;

    (void)argc, argv;

    if (platform_init() != 0)
    {
        (void)printf("Cannot initialize platform.");
        result = __LINE__;
    }
    else
    {
        const IO_INTERFACE_DESCRIPTION* tlsio_interface = platform_get_default_tlsio();
        if (tlsio_interface == NULL)
        {
            (void)printf("Error getting tlsio interface description.");
            result = __LINE__;
        }
        else
        {
            TLSIO_CONFIG tlsio_config;

            tlsio_config.hostname = "iot-sdks-test.azure-devices.net";
            tlsio_config.port = 443;
            tlsio = xio_create(tlsio_interface, &tlsio_config);
            if (tlsio == NULL)
            {
                (void)printf("Error creating tlsio.");
                result = __LINE__;
            }
            else
            {
                wsio_config.hostname = "iot-sdks-test.azure-devices.net";
                wsio_config.underlying_io = tlsio;

                const IO_INTERFACE_DESCRIPTION* wsio_interface = wsio_get_interface_description();
                if (wsio_interface == NULL)
                {
                    (void)printf("Error getting wsio interface description.");
                    result = __LINE__;
                }
                else
                {
                    wsio = xio_create(wsio_interface, &wsio_config);
                    if (wsio == NULL)
                    {
                        (void)printf("Error creating wsio.");
                        result = __LINE__;
                    }
                    else
                    {
                        if (xio_open(wsio, on_io_open_complete, wsio, on_io_bytes_received, wsio, on_io_error, wsio) != 0)
                        {
                            (void)printf("Error opening wsio.");
                            result = __LINE__;
                        }
                        else
                        {
                            while (1)
                            {
                                xio_dowork(wsio);
                            }

                            result = 0;
                        }
                    }
                }

                xio_destroy(tlsio);
            }
        }
    }

    return result;
}

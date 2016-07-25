// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "Arduino.h"

#include "azure_c_shared_utility/threadapi.h"

void ThreadAPI_Sleep(unsigned int milliseconds)
{
    delay(milliseconds);
}

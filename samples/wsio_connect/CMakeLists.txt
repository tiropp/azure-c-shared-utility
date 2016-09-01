#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

compileAsC99()

set(wsio_connect_c_files
    main.c
)

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
ENDIF(WIN32)

add_executable(wsio_connect ${wsio_connect_c_files})

target_link_libraries(wsio_connect 
    aziotsharedutil
)

set_target_properties(wsio_connect
			   PROPERTIES
			   FOLDER "azure_c_shared_utility_samples")

#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)
project(poc_custom_hsm)

#Use solution folders.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Creating 
set(PROVIONING_INCLUDE_DIR "../azure-iot-sdk-c/provisioning_client/adapters")

if("${OPENSSL_ROOT_DIR}" STREQUAL "" AND NOT ("$ENV{OpenSSLDir}" STREQUAL ""))
    set(OPENSSL_ROOT_DIR $ENV{OpenSSLDir} CACHE PATH "")
endif()

#find_package(OpenSSL REQUIRED)
include_directories(. ./inc ${PROVIONING_INCLUDE_DIR})

set(source_c_files
    ./src/custom_hsm_impl.c
    ./src/tpm_impl.c
    ./src/x509_impl.c
)

set(source_h_files
    ./inc/tpm_impl.h
    ./inc/x509_impl.h
)

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)

    # Make warning as error
    add_definitions(/WX)
ELSE()
    # Make warning as error
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -fPIC")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
ENDIF(WIN32)

add_library(poc_custom_hsm ${source_c_files} ${source_h_files})

add_subdirectory(./sample)
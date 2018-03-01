#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)
project(poc_custom_hsm)

#Use solution folders.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(azure_iot_dir "The directory of the azure iot sdk directory")

if ("${azure_iot_dir}" STREQUAL "")
    #see if the azure iot directory is in the same path

endif()

# Azure Provisioning include directory
set(PROVIONING_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../azure-iot-sdk-c/provisioning_client/adapters")

message(STATUS "prov: ${PROVIONING_INCLUDE_DIR}")

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

add_library(custom_hsm ${source_c_files} ${source_h_files})

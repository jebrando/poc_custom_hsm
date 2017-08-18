// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "custom_hsm_impl.h"

typedef struct CUSTOM_HSM_IMPL_TAG
{
    int j;
} CUSTOM_HSM_IMPL;


DPS_CUSTOM_HSM_HANDLE custom_hsm_create()
{
    CUSTOM_HSM_IMPL* result;
    result = malloc(sizeof(CUSTOM_HSM_IMPL));
    if (result == NULL)
    {
        (void)printf("Failure: malloc CUSTOM_HSM_IMPL.");
    }
    else
    {
        memset(result, 0, sizeof(CUSTOM_HSM_IMPL));
    }
    return (DPS_CUSTOM_HSM_HANDLE)result;
}

void custom_hsm_destroy(DPS_CUSTOM_HSM_HANDLE handle)
{
    if (handle != NULL)
    {
        CUSTOM_HSM_IMPL* hsm_impl = (CUSTOM_HSM_IMPL*)handle;
        free(hsm_impl);
    }
}

char* custom_hsm_get_certificate(DPS_CUSTOM_HSM_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        // allocate certificate and return
        result = "certificate";
        if (result == NULL)
        {
            (void)printf("Failure retrieving certificate from custom HSM.");
        }
    }
    return result;
}

char* custom_hsm_get_alias_key(DPS_CUSTOM_HSM_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        // allocate certificate and return
        result = "alias Key";
    }
    return result;
}

char* custom_hsm_get_get_signer_cert(DPS_CUSTOM_HSM_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        result = "signer cert";
        if (result == NULL)
        {
            (void)printf("Failure retrieving alias key from custom HSM.");
        }
    }
    return result;
}

char* dps_hsm_custom_get_common_name(DPS_CUSTOM_HSM_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        // Return the common name from the certificate
        result = "common_name";
        if (result == NULL)
        {
            (void)printf("Failure retrieving common name from custom HSM.");
        }
    }
    return result;
}

// TPM Custom Information handling
int custom_hsm_get_endorsement_key(DPS_CUSTOM_HSM_HANDLE handle, unsigned char** key, size_t* key_len)
{
    int result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = __LINE__;
    }
    else
    {
        *key = malloc(1);
        *key_len = 1;
        result = 0;
    }
    return result;
}

int custom_hsm_get_storage_root_key(DPS_CUSTOM_HSM_HANDLE handle, unsigned char** key, size_t* key_len) 
{
    int result;
    if (handle == NULL || key == NULL || key_len == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = __LINE__;
    }
    else
    {
        *key = malloc(1);
        *key_len = 1;
        result = 0;
    }
    return result;
}

int custom_hsm_import_key(DPS_CUSTOM_HSM_HANDLE handle, const unsigned char* key, size_t key_len)
{
    int result;
    if (handle == NULL || key == NULL || key_len == 0)
    {
        (void)printf("Invalid argument specified handle: %p, key: %p, key_len: %d", handle, key, key_len);
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

int custom_hsm_sign_key(DPS_CUSTOM_HSM_HANDLE handle, const unsigned char* data, size_t data_len, unsigned char** signed_value, size_t* signed_len) 
{
    int result;
    if (handle == NULL || data == NULL || data_len == 0 || signed_value == NULL || signed_len == NULL)
    {
        (void)printf("Invalid handle value specified handle: %p, data: %p", handle, data);
        result = __LINE__;
    }
    else
    {
        *signed_value = malloc(1);
        *signed_len = 1;
        result = 0;
    }
    return result;
}

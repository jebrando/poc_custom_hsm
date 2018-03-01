// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <string.h>

#include "tpm_impl.h"

static const int KEY_SIZE = 2048;
const int kExp = 3;

typedef struct TPM_INFO_TAG
{
    unsigned char* key;
} TPM_INFO;

static bool initialize_keys(TPM_INFO* openssl_info)
{
    return false;
}

TPM_HANDLE tpm_impl_create(void)
{
    TPM_INFO* result;
    if ((result = (TPM_INFO*)malloc(sizeof(TPM_INFO))) == NULL)
    {
        result = NULL;
    }
    else
    {
        memset(result, 0, sizeof(TPM_INFO));
    }
    return result;
}

void tpm_impl_destroy(TPM_HANDLE handle)
{
    if (handle != NULL)
    {
        //RSA_free(handle->rsa_key);
        free(handle);
    }
}

const unsigned char* tpm_impl_retrieve_ek(TPM_HANDLE handle, size_t* length)
{
    const unsigned char* result;
    if (handle == NULL || length == NULL)
    {
        result = NULL;
    }
    else
    {
        // TODO: get the ek
        result = NULL;
    }
    return result;
}

const unsigned char* tpm_impl_retrieve_srk(TPM_HANDLE handle, size_t* length)
{
    const unsigned char* result;
    if (handle == NULL || length == NULL)
    {
        result = NULL;
    }
    else
    {
        // TODO: get the srk
        result = NULL;
    }
    return result;
}

int tpm_impl_insert_key(TPM_HANDLE handle, const unsigned char* key_value, size_t length)
{
    int result;
    if (handle == NULL || key_value == NULL || length == 0)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

int tpm_impl_hash_data(TPM_HANDLE handle, const unsigned char* data, size_t length)
{
    int result;
    if (handle == NULL || data == NULL || length == 0)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

const char* tpm_impl_get_last_error(TPM_HANDLE handle)
{
    const char* result;
    if (handle == NULL)
    {
        result = "invalid_parameter";
    }
    else
    {
        result = "error";
    }
    return result;
}
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "tpm_openssl.h"

typedef struct TPM_OPENSSL_INFO_TAG
{
    RSA* rsa_key;
    char* hash_key;
} TPM_OPENSSL_INFO;

TPM_OPENSSL_HANDLE tpm_openssl_create(void)
{
    TPM_OPENSSL_INFO* result;
    if ((result = (TPM_OPENSSL_INFO*)malloc(sizeof(TPM_OPENSSL_INFO))) == NULL)
    {
    }
    else
    {
        memset(result, 0, sizeof(TPM_OPENSSL_INFO));
    }
    return result;
}

void tpm_openssl_destroy(TPM_OPENSSL_HANDLE handle)
{
    if (handle != NULL)
    {
        free(handle);
    }
}

int tpm_openssl_retrieve_ek(TPM_OPENSSL_HANDLE handle, unsigned char* key_value, size_t length)
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

int tpm_openssl_retrieve_srk(TPM_OPENSSL_HANDLE handle, unsigned char* key_value, size_t length)
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

int tpm_openssl_insert_key(TPM_OPENSSL_HANDLE handle, const unsigned char* key_value, size_t length)
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

int tpm_openssl_hash_data(TPM_OPENSSL_HANDLE handle, const unsigned char* data, size_t length)
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

const char* tpm_openssl_get_last_error(TPM_OPENSSL_HANDLE handle)
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

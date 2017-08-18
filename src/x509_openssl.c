// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "x509_openssl.h"

typedef struct X509_OPENSSL_INFO_TAG
{
    RSA* rsa_key;
    char* hash_key;
} X509_OPENSSL_INFO;

X509_OPENSSL_HANDLE x509_openssl_create(void)
{
    X509_OPENSSL_INFO* result;
    if ((result = (X509_OPENSSL_INFO*)malloc(sizeof(X509_OPENSSL_INFO))) == NULL)
    {
    }
    else
    {
        memset(result, 0, sizeof(X509_OPENSSL_INFO));
    }
    return result;
}

void x509_openssl_destroy(X509_OPENSSL_HANDLE handle)
{
    if (handle != NULL)
    {
        free(handle);
    }
}

int x509_openssl_retrieve_ek(X509_OPENSSL_HANDLE handle, unsigned char* key_value, size_t length)
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

int x509_openssl_retrieve_srk(X509_OPENSSL_HANDLE handle, unsigned char* key_value, size_t length)
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

int x509_openssl_insert_key(X509_OPENSSL_HANDLE handle, const unsigned char* key_value, size_t length)
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

int x509_openssl_hash_data(X509_OPENSSL_HANDLE handle, const unsigned char* data, size_t length)
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

const char* x509_openssl_get_last_error(X509_OPENSSL_HANDLE handle)
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

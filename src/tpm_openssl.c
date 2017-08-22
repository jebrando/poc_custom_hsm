// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "tpm_openssl.h"

static const int KEY_SIZE = 2048;
const int kExp = 3;

typedef struct TPM_OPENSSL_INFO_TAG
{
    RSA* rsa_ek;
    RSA* rsa_srk;
    char* hash_key;
} TPM_OPENSSL_INFO;

static RSA* generate_key()
{
    const unsigned long e = RSA_F4;
    RSA* result;
    BIGNUM* bne = NULL;

    if ((bne = BN_new()) == NULL)
    {
        result = NULL;
    }
    else if (BN_set_word(bne, e) != 1)
    {
        result = NULL;
        BN_free(bne);
    }
    else
    {
        if ((result = RSA_new()) == NULL)
        {
        }
        else if (RSA_generate_key_ex(result, KEY_SIZE, bne, NULL) != 1)
        {
            free(result);
            result = NULL;
        }
        BN_free(bne);
    }
    return result;
}

TPM_OPENSSL_HANDLE tpm_openssl_create(void)
{
    TPM_OPENSSL_INFO* result;
    if ((result = (TPM_OPENSSL_INFO*)malloc(sizeof(TPM_OPENSSL_INFO))) == NULL)
    {
        result = NULL;
    }
    else
    {
        memset(result, 0, sizeof(TPM_OPENSSL_INFO));

        if ((result->rsa_ek = generate_key()) == NULL)
        {
            free(result);
            result = NULL;
        }
        else if ((result->rsa_srk = generate_key()) == NULL)
        {
            RSA_free(result->rsa_ek);
            free(result);
            result = NULL;
        }
        else
        {

        }
    }
    return result;
}

void tpm_openssl_destroy(TPM_OPENSSL_HANDLE handle)
{
    if (handle != NULL)
    {
        RSA_free(handle->rsa_ek);
        RSA_free(handle->rsa_srk);
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
        BIO* bp_public = NULL;
        //bp_public = BIO_new_file("ek_rsa_pk.pem", "w+");
        bp_public = BIO_new(BIO_s_mem());
        //void* buf;
        //BIO_get_mem_ptr(bp_public, &buf);


        if (PEM_write_bio_RSAPublicKey(bp_public, handle->rsa_ek) != 1)
        {
            printf("Failed writing RSA PK");
        }
        else
        {
            void* buf;
            BIO_get_mem_ptr(bp_public, &buf);


            // Copy to key_value
        }
        BIO_free_all(bp_public);
        //BIO_free_all(bp_private);
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

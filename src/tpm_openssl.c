// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <string.h>

//#include <openssl/rsa.h>
//#include <openssl/pem.h>

#include "tpm_openssl.h"

static const int KEY_SIZE = 2048;
const int kExp = 3;

typedef struct TPM_OPENSSL_INFO_TAG
{
/*    RSA* rsa_key;
    RSA* rsa_srk;
    char* hash_key;

    EVP_PKEY* local_key_pair;
    EVP_PKEY* remotePubKey;

    EVP_CIPHER_CTX* rsaEncryptCtx;
    EVP_CIPHER_CTX* rsa_decrypt_ctx;*/

    unsigned char *aesKey;
    unsigned char *aesIV;
} TPM_OPENSSL_INFO;

/*static RSA* generate_key()
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
            result = NULL;
        }
        else if (RSA_generate_key_ex(result, KEY_SIZE, bne, NULL) != 1)
        {
            free(result);
            result = NULL;
        }
        else
        {
            //RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

            BIO *pri = BIO_new(BIO_s_mem());
            BIO *pub = BIO_new(BIO_s_mem());

            PEM_write_bio_RSAPrivateKey(pri, result, NULL, NULL, 0, NULL, NULL);
            PEM_write_bio_RSAPublicKey(pub, result);

            size_t pri_len = BIO_pending(pri);
            size_t pub_len = BIO_pending(pub);

            char *pri_key = malloc(pri_len + 1);
            char *pub_key = malloc(pub_len + 1);

            BIO_read(pri, pri_key, pri_len);
            BIO_read(pub, pub_key, pub_len);

            pri_key[pri_len] = '\0';
            pub_key[pub_len] = '\0';

            printf("\n%s\n%s\n", pri_key, pub_key);
        }
        BN_free(bne);
    }
    return result;
}*/

static bool initialize_keys(TPM_OPENSSL_INFO* openssl_info)
{

    //openssl_info->rsa_decrypt_ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    //openssl_info->rsa_decrypt_ctx.
    return false;
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
        /*if ((result->rsa_key = generate_key()) == NULL)
        {
            free(result);
            result = NULL;
        }
        else
        {
        }*/
    }
    return result;
}

void tpm_openssl_destroy(TPM_OPENSSL_HANDLE handle)
{
    if (handle != NULL)
    {
        //RSA_free(handle->rsa_key);
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
        /*BIO* bp_public = BIO_new(BIO_s_mem());
        BIO* bp_private = BIO_new(BIO_s_mem());

        if (PEM_write_bio_RSAPublicKey(bp_public, handle->rsa_key) != 1)
        {
            printf("Failed writing RSA Public Key");
            result = __LINE__;
        }
        //else if (PEM_write_bio_RSAPrivateKey(bp_private, handle->rsa_key, NULL, NULL) != 1)
        //{
        //    printf("Failed writing RSA Private Key");
        //    result = __LINE__;
        //}
        else
        {
            void* buf;
            BIO_get_mem_ptr(bp_public, &buf);

            result = 0;
            // Copy to key_value
        }
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);*/
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

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x509_impl.h"
#include "tpm_impl.h"

#include "hsm_client_data.h"

typedef struct CUSTOM_HSM_IMPL_TAG
{
    X509_HANDLE x509_impl;
    TPM_HANDLE tmp_impl;
} CUSTOM_HSM_IMPL;

HSM_CLIENT_HANDLE custom_hsm_create()
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
        result->x509_impl = x509_impl_create();
        if (result->x509_impl == NULL)
        {
            (void)printf("Failure: x509 openssl create failed.");
            free(result);
            result = NULL;
        }
        else // Create TPM
        {
            result->tmp_impl = tpm_impl_create();
            if (result->tmp_impl == NULL)
            {
                (void)printf("Failure: tpm openssl create failed.");
                x509_impl_destroy(result->x509_impl);
                free(result);
                result = NULL;
            }
        }
    }
    return (HSM_CLIENT_HANDLE)result;
}

void custom_hsm_destroy(HSM_CLIENT_HANDLE handle)
{
    if (handle != NULL)
    {
        CUSTOM_HSM_IMPL* hsm_impl = (CUSTOM_HSM_IMPL*)handle;
        x509_impl_destroy(hsm_impl->x509_impl);
        free(hsm_impl);
    }
}

char* custom_hsm_get_certificate(HSM_CLIENT_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        CUSTOM_HSM_IMPL* cust_hsm = (CUSTOM_HSM_IMPL*)handle;
        const char* cert = x509_impl_retrieve_cert(cust_hsm->x509_impl);
        if (cert == NULL)
        {
            (void)printf("Failure retrieving cert");
            result = NULL;
        }
        else
        {
            size_t length = strlen(cert);
            result = malloc(length + 1);
            if (result == NULL)
            {
                (void)printf("Failure allocating certifiicate");
            }
            else
            {
                strcpy(result, cert);
            }
        }
    }
    return result;
}

char* custom_hsm_get_alias_key(HSM_CLIENT_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        CUSTOM_HSM_IMPL* cust_hsm = (CUSTOM_HSM_IMPL*)handle;
        const char* private_key = x509_impl_retrieve_key_alias(cust_hsm->x509_impl);
        if (private_key == NULL)
        {
            (void)printf("Failure retrieving private key");
            result = NULL;
        }
        else
        {
            size_t length = strlen(private_key);
            result = malloc(length + 1);
            if (result == NULL)
            {
                (void)printf("Failure allocating private key");
            }
            else
            {
                strcpy(result, private_key);
            }
        }
    }
    return result;
}

char* custom_hsm_get_common_name(HSM_CLIENT_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = NULL;
    }
    else
    {
        CUSTOM_HSM_IMPL* cust_hsm = (CUSTOM_HSM_IMPL*)handle;
        const char* common_name = x509_impl_cert_common_name(cust_hsm->x509_impl);
        if (common_name == NULL)
        {
            (void)printf("Failure retrieving common name");
            result = NULL;
        }
        else
        {
            size_t length = strlen(common_name);
            result = malloc(length + 1);
            if (result == NULL)
            {
                (void)printf("Failure allocating common name");
            }
            else
            {
                strcpy(result, common_name);
            }
        }
    }
    return result;
}

// TPM Custom Information handling
int custom_hsm_get_endorsement_key(HSM_CLIENT_HANDLE handle, unsigned char** key, size_t* key_len)
{
    int result;
    if (handle == NULL || key == NULL || key_len == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = __LINE__;
    }
    else
    {
        size_t ek_len;
        CUSTOM_HSM_IMPL* cust_hsm = (CUSTOM_HSM_IMPL*)handle;
        const unsigned char* ek = tpm_impl_retrieve_ek(cust_hsm->tmp_impl, &ek_len);
        if (ek == NULL)
        {
            result = __LINE__;
        }
        else
        {
            key = malloc(ek_len);
            if (key == NULL)
            {
                (void)printf("Failure allocating common name");
                result = __LINE__;
            }
            else
            {
                memcpy(key, ek, ek_len);
                *key_len = ek_len;
                result = 0;
            }
        }
    }
    return result;
}

int custom_hsm_get_storage_root_key(HSM_CLIENT_HANDLE handle, unsigned char** key, size_t* key_len) 
{
    int result;
    if (handle == NULL || key == NULL || key_len == NULL)
    {
        (void)printf("Invalid handle value specified");
        result = __LINE__;
    }
    else
    {
        size_t srk_len;
        CUSTOM_HSM_IMPL* cust_hsm = (CUSTOM_HSM_IMPL*)handle;
        const unsigned char* srk = tpm_impl_retrieve_srk(cust_hsm->tmp_impl, &srk_len);
        if (srk == NULL)
        {
            result = __LINE__;
        }
        else
        {
            key = malloc(srk_len);
            if (key == NULL)
            {
                (void)printf("Failure allocating common name");
                result = __LINE__;
            }
            else
            {
                memcpy(key, srk, srk_len);
                *key_len = srk_len;
                result = 0;
            }
        }
    }
    return result;
}

int custom_hsm_activate_id_key(HSM_CLIENT_HANDLE handle, const unsigned char* key, size_t key_len)
{
    int result;
    if (handle == NULL || key == NULL || key_len == 0)
    {
        (void)printf("Invalid argument specified handle: %p, key: %p, key_len: %d", handle, key, (int)key_len);
        result = __LINE__;
    }
    else
    {
        result = __LINE__;
    }
    return result;
}

int custom_hsm_sign_with_identity(HSM_CLIENT_HANDLE handle, const unsigned char* data, size_t data_len, unsigned char** signed_value, size_t* signed_len)
{
    int result;
    if (handle == NULL || data == NULL || data_len == 0 || signed_value == NULL || signed_len == NULL)
    {
        (void)printf("Invalid handle value specified handle: %p, data: %p", handle, data);
        result = __LINE__;
    }
    else
    {
        result = __LINE__;
    }
    return result;
}

static const HSM_CLIENT_X509_INTERFACE x509_interface =
{
    custom_hsm_create,
    custom_hsm_destroy,
    custom_hsm_get_certificate,
    custom_hsm_get_alias_key,
    custom_hsm_get_common_name
};

static const HSM_CLIENT_TPM_INTERFACE tpm_interface =
{
    custom_hsm_create,
    custom_hsm_destroy,
    custom_hsm_activate_id_key,
    custom_hsm_get_endorsement_key,
    custom_hsm_get_storage_root_key,
    custom_hsm_sign_with_identity
};

int hsm_client_x509_init()
{
    return 0;
}

void hsm_client_x509_deinit()
{
}

int hsm_client_tpm_init()
{
    return 0;
}

void hsm_client_tpm_deinit()
{
}

const HSM_CLIENT_TPM_INTERFACE* hsm_client_tpm_interface()
{
    return &tpm_interface;
}

const HSM_CLIENT_X509_INTERFACE* hsm_client_x509_interface()
{
    return &x509_interface;
}

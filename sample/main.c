// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "tpm_openssl.h"

int main(void)
{
    int result;

    //(void)SSL_library_init();

    TPM_OPENSSL_HANDLE handle = tpm_openssl_create();
    if (handle == NULL)
    {
        result = __LINE__;
    }
    else
    {
        unsigned char ek[2048];

        tpm_openssl_retrieve_ek(handle, ek, 2048);

        tpm_openssl_destroy(handle);
    }

    return result;
}
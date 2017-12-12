// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>

#include "hsm_client_data.h"

void process_tpm_functions(const HSM_CLIENT_TPM_INTERFACE* tpm_functions)
{
    HSM_CLIENT_HANDLE handle = tpm_functions->hsm_client_tpm_create();
    if (handle == NULL)
    {
        (void)printf("Failure creating tpm certificate information\r\n");
    }
    else
    {
        unsigned char* ek_value;
        size_t len;
        if (tpm_functions->hsm_client_get_ek(handle, &ek_value, &len) == 0)
        {
            free(ek_value);
        }
        // TODO: update tpm functions
        //tpm_functions->hsm_client_get_srk()
        tpm_functions->hsm_client_tpm_destroy(handle);
    }
}

void process_x509_functions(const HSM_CLIENT_X509_INTERFACE* x509_functions)
{
    HSM_CLIENT_HANDLE handle = x509_functions->hsm_client_x509_create();
    if (handle == NULL)
    {
        (void)printf("Failure creating x509 certificate information\r\n");
    }
    else
    {
        char* x509_data;

        x509_data = x509_functions->hsm_client_get_cert(handle);
        if (x509_data != NULL)
        {
            (void)printf("Certificate:\r\n%s\r\n", x509_data);
            free(x509_data);
        }

        x509_data = x509_functions->hsm_client_get_key(handle);
        if (x509_data != NULL)
        {
            (void)printf("Private Key:\r\n%s\r\n", x509_data);
            free(x509_data);
        }

        x509_data = x509_functions->hsm_client_get_common_name(handle);
        if (x509_data != NULL)
        {
            (void)printf("Common Name:\r\n%s\r\n", x509_data);
            free(x509_data);
        }
        x509_functions->hsm_client_x509_destroy(handle);
    }
}

int main(void)
{
    int result;

    const HSM_CLIENT_TPM_INTERFACE* tpm_functions = hsm_client_tpm_interface();
    const HSM_CLIENT_X509_INTERFACE* x509_functions = hsm_client_x509_interface();

    if (tpm_functions == NULL || x509_functions == NULL)
    {
        (void)printf("HSM functions return NULL\r\n");
        result = __LINE__;
    }
    else
    {
        process_tpm_functions(tpm_functions);
        process_x509_functions(x509_functions);
        result = 0;
    }

    (void)printf("Press any key to continue: ");
    (void)getchar();

    return result;
}
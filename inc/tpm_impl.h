// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TPM_OPENSSL
#define TPM_OPENSSL

#ifdef __cplusplus
#include <cstddef>
#include <cstdbool>
extern "C"
{
#else
#include <stddef.h>
#include <stdbool.h>
#endif

typedef struct TPM_INFO_TAG* TPM_HANDLE;

extern TPM_HANDLE tpm_openssl_create(void);
extern void tpm_openssl_destroy(TPM_HANDLE handle);

extern int tpm_openssl_retrieve_ek(TPM_HANDLE handle, unsigned char* key_value, size_t length);
extern int tpm_openssl_retrieve_srk(TPM_HANDLE handle, unsigned char* key_value, size_t length);

extern int tpm_openssl_insert_key(TPM_HANDLE handle, const unsigned char* key_value, size_t length);

extern int tpm_openssl_hash_data(TPM_HANDLE handle, const unsigned char* data, size_t length);

extern const char* tpm_openssl_get_last_error(TPM_HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif // !TPM_OPENSSL

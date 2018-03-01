// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TPM_IMPL
#define TPM_IMPL

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

extern TPM_HANDLE tpm_impl_create(void);
extern void tpm_impl_destroy(TPM_HANDLE handle);

extern const unsigned char* tpm_impl_retrieve_ek(TPM_HANDLE handle, size_t* length);
extern const unsigned char* tpm_impl_retrieve_srk(TPM_HANDLE handle, size_t* length);

extern int tpm_impl_insert_key(TPM_HANDLE handle, const unsigned char* key_value, size_t length);

extern int tpm_impl_hash_data(TPM_HANDLE handle, const unsigned char* data, size_t length);

extern const char* tpm_impl_get_last_error(TPM_HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif // !TPM_IMPL

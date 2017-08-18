// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef X509_OPENSSL
#define X509_OPENSSL

#ifdef __cplusplus
#include <cstddef>
#include <cstdbool>
extern "C"
{
#else
#include <stddef.h>
#include <stdbool.h>
#endif

typedef struct X509_OPENSSL_INFO_TAG* X509_OPENSSL_HANDLE;

extern X509_OPENSSL_HANDLE x509_openssl_create(void);
extern void x509_openssl_destroy(X509_OPENSSL_HANDLE handle);

extern int x509_openssl_retrieve_ek(X509_OPENSSL_HANDLE handle, unsigned char* key_value, size_t length);
extern int x509_openssl_retrieve_srk(X509_OPENSSL_HANDLE handle, unsigned char* key_value, size_t length);

extern int x509_openssl_insert_key(X509_OPENSSL_HANDLE handle, const unsigned char* key_value, size_t length);

extern int x509_openssl_hash_data(X509_OPENSSL_HANDLE handle, const unsigned char* data, size_t length);

extern const char* x509_openssl_get_last_error(X509_OPENSSL_HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif // !X509_OPENSSL

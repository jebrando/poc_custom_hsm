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

typedef struct X509_INFO_TAG* X509_HANDLE;

extern int initialize_x509(X509_HANDLE handle);
extern void deitialize_x509(X509_HANDLE handle);

extern X509_HANDLE x509_impl_create(void);
extern void x509_impl_destroy(X509_HANDLE handle);

extern const char* x509_impl_retrieve_cert(X509_HANDLE handle);
extern const char* x509_impl_retrieve_key_alias(X509_HANDLE handle);
extern const char* x509_impl_cert_common_name(X509_HANDLE handle);
extern const char* x509_impl_get_last_error(X509_HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif // !X509_OPENSSL

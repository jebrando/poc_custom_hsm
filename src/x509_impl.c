// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <string.h>

//#include <openssl/rsa.h>
//#include <openssl/pem.h>

#include "x509_impl.h"

// Certificate or certificate chain
static const char* X509_CERTIFICATE = "-----BEGIN CERTIFICATE-----""\n"
"MIICpDCCAYwCCQCgAJQdOd6dNzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTcwMTIwMTkyNTMzWhcNMjcwMTE4MTkyNTMzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlJ3fRNWm05BRAhgUY7cpzaxHZIORomZaOp2Uua5yv+psdkpv35ExLhKGrUIK1AJLZylnue0ohZfKPFTnoxMHOecnaaXZ9RA25M7XGQvw85ePlGOZKKf3zXw3Ds58GFY6Sr1SqtDopcDuMmDSg/afYVvGHDjb2Fc4hZFip350AADcmjH5SfWuxgptCY2Jl6ImJoOpxt+imWsJCJEmwZaXw+eZBb87e/9PH4DMXjIUFZebShowAfTh/sinfwRkaLVQ7uJI82Ka/icm6Hmr56j7U81gDaF0DhC03ds5lhN7nMp5aqaKeEJiSGdiyyHAescfxLO/SMunNc/eG7iAirY7BAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACU7TRogb8sEbv+SGzxKSgWKKbw+FNgC4Zi6Fz59t+4jORZkoZ8W87NM946wvkIpxbLKuc4F+7nTGHHksyHIiGC3qPpi4vWpqVeNAP+kfQptFoWEOzxD7jQTWIcqYhvssKZGwDk06c/WtvVnhZOZW+zzJKXA7mbwJrfp8VekOnN5zPwrOCumDiRX7BnEtMjqFDgdMgs9ohR5aFsI7tsqp+dToLKaZqBLTvYwCgCJCxdg3QvMhVD8OxcEIFJtDEwm3h9WFFO3ocabCmcMDyXUL354yaZ7RphCBLd06XXdaUU/eV6fOjY6T5ka4ZRJcYDJtjxSG04XPtxswQfrPGGoFhk=""\n"
"-----END CERTIFICATE-----""\n";

// Private key
static const char* X509_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----""\n"
"MIIEpAIBAAKCAQEA5Sd30TVptOQUQIYFGO3Kc2sR2SDkaJmWjqdlLmucr/qbHZKb9+RMS4Shq1CCtQCS2cpZ7ntKIWXyjxU56MTBznnJ2ml2fUQNuTO1xkL8POXj5RjmSin9818Nw7OfBhWOkq9UqrQ6KXA7jJg0oP2n2Fbxhw429hXOIWRYqd+dAAA3Jox+Un1rsYKbQmNiZeiJiaDqcbfoplrCQiRJsGWl8PnmQW/O3v/Tx+AzF4yFBWXm0oaMAH04f7Ip38EZGi1UO7iSPNimv4nJuh5q+eo+1PNYA2hdA4QtN3bOZYTe5zKeWqminhCYkhnYsshwHrHH8Szv0jLpzXP3hu4gIq2OwQIDAQABAoIBAQCwO9RYHz32klpI7UlKTMagUT3ewP8ousYhW/fi5XwRkyhsa+5rjTZn9c7oE/kR/yjxOkBDuqneWatcAzUQIRH0G5Hz2Zv45revMWeg3K9knmDQNoAVlYnq+7V4RtIMOdP2V8VDq2v3posFq6D+F1ZYeTUzauk2BLsMz0GpE4KJFizAffTvYwQfOTtvKXRI9EwHLKlTs8bfqVw09LRp6CbEuARf+OEeHNg3shXxN0mAGjtynUVK6rIbipAiQm1zYDtvahaOCJIm/G+DQvY1nrgxW2BsgLT0/VxTgRmgS5BkPMvH+L+u9CN7dv6d9K4ENu8LOWhGV7eO6zUk6lXzqzuBAoGBAPU76nkDm9tt6xcCTtg7IRMQLWlJ0g3sq58E5xvjALdqAxwVibjsuPxgz4C7jcE/cptymJ1ip1cIwJM2924ZltsJBbMZKxcjWVbj6lubhJtK5LTpdz7uVSxxNI3Ywp+64bKEKZkXJzUs+avJL7zYzZQoqLY5nWAKKvuBlvLHgjCpAoGBAO821knJ60RpHB68dEt/kVgqJtt99B+5Oc9E1TD6kMLxjSXR6PHhGWQxu4LFaXwHMEHAIAiPWYmf1nUPwoc0kc5/0rpyZjfVkhZ/w4TD/FlFeGgfaVV6RxTsls3n8awprdbgmuCUjiJAbm9Nb6P1uiu/SlsEqJsW9ytBpzXRaARZAoGAIpvnFlcFCu2zTNb9i5SksU0KK57Ib0CkY9fMSeo6cqgacj8z5Y46+Rssja1qbwhmQzvj/+opVaYdj2kleDtSR+05CbKWmzhY5mNZ8r269DOYnVOJia8XBCOh2BbsOKCmM4xlVn6nAOEtBypoe01ZjfxC+xycci5dLIt4YyD25akCgYEAqvCU0MXpyUkTPyOMNydBxa7ZdZ/cA49pMCQP9KAZMjVKl+wYekBQ1Lh1Nk27w1WftlyEh5locmA18BEDAXsfdmEBRRra0KtdaZaDMSyb928dS8qmit6GTP2EBj/pAw4Fm7eE9Vcy+mbwg7jiPlgqYXigucnqcmlG1zJjOqIZooECgYB+qpGqH37NaIb+TDOYP40zpOWAkc2l6hy8nx3G9yNaR/Wb3uvYgCBGPxkL7bBgoT1w9S+f99TEXOiXUdrl34m/QJ446Rb6aNbqVLcDwLcXL4h2zFXVRGo35lmm6kCRa9Ohnhe1DwQK6C1SMngUitaTHhjTtjKNXJrdWPMVUUYEGw==""\n"
"-----END RSA PRIVATE KEY-----""\n";

static const char* X509_COMMON_NAME = "localhost";

typedef struct X509_INFO_TAG
{
    //RSA* rsa_key;
    char* hash_key;
} X509_INFO;

X509_HANDLE x509_openssl_create(void)
{
    X509_INFO* result;
    if ((result = (X509_INFO*)malloc(sizeof(X509_INFO))) == NULL)
    {
    }
    else
    {
        memset(result, 0, sizeof(X509_INFO));
    }
    return result;
}

void x509_openssl_destroy(X509_HANDLE handle)
{
    if (handle != NULL)
    {
        free(handle);
    }
}

int initialize_x509(X509_HANDLE handle)
{
    // Read the cert from disk or create it
    return 0;
}

void deitialize_x509(X509_HANDLE handle)
{

}

const char* x509_openssl_retrieve_cert(X509_HANDLE handle)
{
    const char* result;
    if (handle == NULL)
    {
        result = NULL;
    }
    else
    {
        result = X509_CERTIFICATE;
    }
    return result;
}

const char* x509_openssl_retrieve_private_key(X509_HANDLE handle)
{
    const char* result;
    if (handle == NULL)
    {
        result = NULL;
    }
    else
    {
        result = X509_PRIVATE_KEY;
    }
    return result;
}

const char* x509_openssl_cert_common_name(X509_HANDLE handle)
{
    const char* result;
    if (handle == NULL)
    {
        result = NULL;
    }
    else
    {
        result = X509_COMMON_NAME;
    }
    return result;
}

const char* x509_openssl_get_last_error(X509_HANDLE handle)
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

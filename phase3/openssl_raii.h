#ifndef OPENSSL_RAII_H
#define OPENSSL_RAII_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <memory>

// Deleter-wrapped unique_ptr aliases for OpenSSL's C-style handles.
// Using these instead of raw pointers means every one of these objects
// is freed automatically on scope exit, on ANY return/throw path,
// without needing matching manual _free() calls at each one.

struct BN_Deleter { void operator()(BIGNUM* bn) const { BN_free(bn); } };
using BN_ptr = std::unique_ptr<BIGNUM, BN_Deleter>;

struct BN_CTX_Deleter { void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); } };
using BN_CTX_ptr = std::unique_ptr<BN_CTX, BN_CTX_Deleter>;

struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); } };
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); } };
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;

// --- New for Phase 3 (PKI) ---

struct X509_Deleter { void operator()(X509* x) const { X509_free(x); } };
using X509_ptr = std::unique_ptr<X509, X509_Deleter>;

struct EVP_PKEY_Deleter { void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); } };
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

struct BIO_Deleter { void operator()(BIO* b) const { BIO_free(b); } };
using BIO_ptr = std::unique_ptr<BIO, BIO_Deleter>;

#endif
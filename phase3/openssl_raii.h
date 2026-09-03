#ifndef OPENSSL_RAII_H
#define OPENSSL_RAII_H

#include <openssl/bn.h>
#include <openssl/evp.h>
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

#endif
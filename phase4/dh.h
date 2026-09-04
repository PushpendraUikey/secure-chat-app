#ifndef DH_H
#define DH_H

#include <openssl/bn.h>
#include <string>
#include "openssl_raii.h"

extern const char* MODP_GROUP14_PRIME_HEX;
constexpr int MODP_GROUP14_GENERATOR = 2;
constexpr size_t MODP_GROUP14_BYTE_LEN = 256; // 2048 bits / 8 — fixed output width

class DiffieHellman {
public:
    DiffieHellman();
    // No destructor needed — BN_ptr/BN_CTX_ptr members clean themselves
    // up automatically via RAII, including if construction throws partway
    // through (each already-constructed member is still destroyed during
    // unwinding;

    void generate_keypair();
    std::string get_public_value_hex() const;
    std::string compute_shared_secret(const std::string& peer_public_hex) const;

private:
    BN_ptr p_;
    BN_ptr g_;
    BN_ptr priv_key_;
    BN_ptr pub_key_;
    BN_CTX_ptr ctx_;
};

#endif
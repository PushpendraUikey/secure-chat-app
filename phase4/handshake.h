#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <string>
#include <array>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "crypto_utils.h"

// Full pre-application handshake, client side. On success, fills
// `session_key` and returns true. On ANY failure — invalid cert,
// failed signature, DH failure — returns false having sent nothing
// past the point of failure, per §4.1's "abort immediately" requirement.
bool client_perform_handshake(
    int sock,
    std::string& pending,
    const std::string& ca_cert_path,
    const std::string& expected_cn,
    std::array<unsigned char, AES_KEY_SIZE>& session_key
);

// Same handshake, server side. `server_cert`/`server_key` are loaded
// ONCE at program startup and passed in — not reloaded per connection.
bool server_perform_handshake(
    int sock,
    std::string& pending,
    X509* server_cert,
    EVP_PKEY* server_key,
    std::array<unsigned char, AES_KEY_SIZE>& session_key
);

#endif
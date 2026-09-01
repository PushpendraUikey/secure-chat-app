#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <array>

constexpr size_t AES_KEY_SIZE = 32; // 256-bit key for AES-256-GCM

// Derives a symmetric AES key from the raw DH shared secret via SHA-256.
// The raw secret itself is never used as a key directly
std::array<unsigned char, AES_KEY_SIZE> derive_key(const std::string& raw_shared_secret);

// Produces a short, human-readable, hash-based fingerprint of the shared
// secret for the required verification step — printed on both ends
// to confirm they derived the identical secret, WITHOUT ever printing the
// raw secret or the derived key itself.
// Format: colon-separated hex, first 8 bytes of SHA-256(secret) — e.g.
// "3f:a1:9c:02:77:8e:5b:d4"
std::string fingerprint(const std::string& raw_shared_secret);

#endif
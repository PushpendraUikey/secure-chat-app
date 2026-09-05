#ifndef AES_GCM_H
#define AES_GCM_H

#include <string>
#include <array>
#include "crypto_utils.h"

constexpr size_t GCM_NONCE_SIZE = 12; // 96-bit nonce,
constexpr size_t GCM_TAG_SIZE = 16;   // 128-bit authentication tag

// Encrypts `plaintext` with AES-256-GCM under `key`.
// Generates a fresh random nonce internally for every call
// Returns a single opaque blob: nonce || ciphertext || tag
std::string encrypt_message(
    const std::array<unsigned char, AES_KEY_SIZE>& key,
    const std::string& plaintext
);

// Decrypts a blob produced by encrypt_message(). Verifies the GCM tag
// as part of decryption — on any tampering (ciphertext OR tag modified),
// this throws rather than returning corrupted plaintext.
std::string decrypt_message(
    const std::array<unsigned char, AES_KEY_SIZE>& key,
    const std::string& blob
);

#endif
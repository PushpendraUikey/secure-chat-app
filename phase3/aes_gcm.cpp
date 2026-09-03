#include "aes_gcm.h"
#include "openssl_raii.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

std::string encrypt_message(
    const std::array<unsigned char, AES_KEY_SIZE>& key,
    const std::string& plaintext) {

    unsigned char nonce[GCM_NONCE_SIZE];
    if (RAND_bytes(nonce, GCM_NONCE_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random nonce");
    }

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to allocate cipher context");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex (algo) failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nullptr) != 1) {
        throw std::runtime_error("Failed to set GCM nonce length");
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex (key/nonce) failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertext_len, &len) != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    unsigned char tag[GCM_TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        throw std::runtime_error("Failed to retrieve GCM tag");
    }

    std::string blob;
    blob.reserve(GCM_NONCE_SIZE + ciphertext_len + GCM_TAG_SIZE);
    blob.append(reinterpret_cast<char*>(nonce), GCM_NONCE_SIZE);
    blob.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    blob.append(reinterpret_cast<char*>(tag), GCM_TAG_SIZE);

    return blob;
}

std::string decrypt_message(
    const std::array<unsigned char, AES_KEY_SIZE>& key,
    const std::string& blob) {

    if (blob.size() < GCM_NONCE_SIZE + GCM_TAG_SIZE) {
        throw std::runtime_error("Blob too short to contain nonce + tag");
    }

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(blob.data());
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(blob.data()) + GCM_NONCE_SIZE;
    size_t ciphertext_len = blob.size() - GCM_NONCE_SIZE - GCM_TAG_SIZE;
    const unsigned char* tag = reinterpret_cast<const unsigned char*>(blob.data()) + GCM_NONCE_SIZE + ciphertext_len;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to allocate cipher context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("EVP_DecryptInit_ex (algo) failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nullptr) != 1) {
        throw std::runtime_error("Failed to set GCM nonce length");
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce) != 1) {
        throw std::runtime_error("EVP_DecryptInit_ex (key/nonce) failed");
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
            ciphertext, static_cast<int>(ciphertext_len)) != 1) {
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
            const_cast<unsigned char*>(tag)) != 1) {
        throw std::runtime_error("Failed to set expected GCM tag");
    }

    // Authentication check — tampering causes this to fail rather than
    // return corrupted plaintext
    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len);

    if (ret <= 0) {
        throw std::runtime_error("GCM authentication failed — message was tampered with or corrupted");
    }
    plaintext_len += len;

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}
#include "crypto_utils.h"
#include "openssl_raii.h"

#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

static std::array<unsigned char, 32> sha256_digest(const std::string& input) {
    std::array<unsigned char, 32> digest{};

    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new());
    if (!mdctx) {
        throw std::runtime_error("Failed to allocate EVP_MD_CTX");
    }

    unsigned int digest_len = 0;

    if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx.get(), input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx.get(), digest.data(), &digest_len) != 1) {
        throw std::runtime_error("SHA-256 digest computation failed");
    }

    return digest;
}

std::array<unsigned char, AES_KEY_SIZE> derive_key(const std::string& raw_shared_secret) {
    static_assert(AES_KEY_SIZE == 32, "AES_KEY_SIZE must match SHA-256 output size");
    return sha256_digest(raw_shared_secret);
}

std::string fingerprint(const std::string& raw_shared_secret) {
    auto digest = sha256_digest(raw_shared_secret);

    std::ostringstream oss;
    for (size_t i = 0; i < 8; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(digest[i]);
    }

    return oss.str();
}
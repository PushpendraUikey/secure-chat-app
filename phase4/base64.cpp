#include "base64.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

std::string base64_encode(const std::string& binary_data) {
    // Upper bound per OpenSSL docs: 4 * ceil(n/3) + null terminator.
    size_t max_len = 4 * ((binary_data.size() + 2) / 3) + 1;
    std::vector<unsigned char> out(max_len);

    int len = EVP_EncodeBlock(
        out.data(),
        reinterpret_cast<const unsigned char*>(binary_data.data()),
        static_cast<int>(binary_data.size())
    );

    if (len < 0) {
        throw std::runtime_error("base64_encode failed");
    }

    return std::string(reinterpret_cast<char*>(out.data()), len);
}

std::string base64_decode(const std::string& encoded) {
    std::vector<unsigned char> out(encoded.size()); // decoded output is always <= input length

    int len = EVP_DecodeBlock(
        out.data(),
        reinterpret_cast<const unsigned char*>(encoded.data()),
        static_cast<int>(encoded.size())
    );

    if (len < 0) {
        throw std::runtime_error("base64_decode failed");
    }

    // EVP_DecodeBlock doesn't strip '=' padding from its output length —
    // trim the 1-2 trailing zero bytes that correspond to padding chars.
    int padding = 0;
    if (encoded.size() >= 2) {
        if (encoded[encoded.size() - 1] == '=') padding++;
        if (encoded[encoded.size() - 2] == '=') padding++;
    }
    len -= padding;

    return std::string(reinterpret_cast<char*>(out.data()), len);
}
#ifndef BASE64_H
#define BASE64_H

#include <string>

// Encodes arbitrary binary data (e.g. an AES-GCM blob containing raw
// bytes including possible 0x0A{newline}) into base64 text, safe to send
// as a single newline-delimited line under the existing framing protocol.
std::string base64_encode(const std::string& binary_data);

// Inverse of base64_encode.
std::string base64_decode(const std::string& encoded);

#endif
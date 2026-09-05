#ifndef PKI_H
#define PKI_H

#include <string>
#include "openssl_raii.h"

// Loads a PEM-encoded X.509 certificate from a file on disk.
X509_ptr load_certificate(const std::string& path);

// Loads a PEM-encoded private key from a file on disk.
EVP_PKEY_ptr load_private_key(const std::string& path);

// Serializes a certificate to a PEM string. NOTE: PEM output contains
// embedded '\n' characters, so — same as our AES-GCM blobs — this MUST
// be passed through base64_encode() before going out as a single line
// under our existing newline-delimited wire framing.
std::string certificate_to_pem(X509* cert);

// Parses a PEM string (received over the wire, already base64-decoded)
// back into a certificate object.
X509_ptr certificate_from_pem(const std::string& pem);

// Validates 'cert' against the trusted 'ca_cert'. Checks, in order:
//   (a) signature: cert was actually signed by ca_cert's key
//   (b) validity period: current time falls within notBefore/notAfter
//   (c) identity: cert's Common Name matches 'expected_cn' exactly
//
// Throws std::runtime_error with a specific, distinguishable reason on
// the FIRST check that fails.
void validate_certificate(X509* cert, X509* ca_cert, const std::string& expected_cn);

// Server-side proof-of-possession: signs 'challenge' with the server's
// private key using RSA + SHA-256. Returns the raw signature bytes.
std::string sign_challenge(EVP_PKEY* private_key, const std::string& challenge);

// Client-side proof-of-possession check: verifies 'signature' over
// 'challenge' using the PUBLIC key embedded in 'cert' (not a separately
// supplied key — this is what ties the proof to the specific certificate
// the client already validated). Returns true only if the signature
// checks out, meaning whoever produced it holds the matching private
// key — not merely a copy of the certificate file.
bool verify_challenge_signature(X509* cert, const std::string& challenge,
                                 const std::string& signature);

#endif
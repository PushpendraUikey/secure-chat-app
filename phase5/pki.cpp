#include "pki.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdexcept>
#include <vector>

// Pulls the OpenSSL error queue into a readable string, since most
// X509/PEM failures otherwise just give you "it returned NULL" with
// no context — makes debugging cert issues far less painful.
static std::string openssl_last_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

X509_ptr load_certificate(const std::string& path) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "r"));
    if (!bio) {
        throw std::runtime_error("Could not open certificate file: " + path);
    }

    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
        throw std::runtime_error("Failed to parse certificate " + path +
                                  ": " + openssl_last_error());
    }

    return X509_ptr(cert);
}

EVP_PKEY_ptr load_private_key(const std::string& path) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "r"));
    if (!bio) {
        throw std::runtime_error("Could not open private key file: " + path);
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        throw std::runtime_error("Failed to parse private key " + path +
                                  ": " + openssl_last_error());
    }

    return EVP_PKEY_ptr(key);
}

std::string certificate_to_pem(X509* cert) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw std::runtime_error("Failed to allocate memory BIO");
    }

    if (PEM_write_bio_X509(bio.get(), cert) != 1) {
        throw std::runtime_error("Failed to serialize certificate to PEM");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || !data) {
        throw std::runtime_error("Failed to read serialized certificate");
    }

    return std::string(data, len);
}

X509_ptr certificate_from_pem(const std::string& pem) {
    BIO_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        throw std::runtime_error("Failed to allocate memory BIO");
    }

    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
        throw std::runtime_error("Failed to parse received certificate PEM: " +
                                  openssl_last_error());
    }

    return X509_ptr(cert);
}

void validate_certificate(X509* cert, X509* ca_cert, const std::string& expected_cn) {
    // (a) Signature: was `cert` actually signed by `ca_cert`'s key?
    EVP_PKEY_ptr ca_pubkey(X509_get_pubkey(ca_cert));
    if (!ca_pubkey) {
        throw std::runtime_error("Could not extract CA public key");
    }

    int verify_result = X509_verify(cert, ca_pubkey.get());
    if (verify_result != 1) {
        throw std::runtime_error(
            "Certificate signature verification FAILED — "
            "this certificate was NOT signed by our trusted CA");
    }

    // (b) Validity period: is 'now' within [notBefore, notAfter]?
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after  = X509_get0_notAfter(cert);

    if (X509_cmp_current_time(not_before) > 0) {
        throw std::runtime_error(
            "Certificate is not yet valid (notBefore is in the future)");
    }
    if (X509_cmp_current_time(not_after) < 0) {
        throw std::runtime_error(
            "Certificate has EXPIRED (notAfter is in the past)");
    }

    // (c) Identity: does the Common Name match who we meant to connect to?
    X509_NAME* subject = X509_get_subject_name(cert);
    if (!subject) {
        throw std::runtime_error("Certificate has no subject name");
    }

    char cn_buf[256] = {0};
    int cn_len = X509_NAME_get_text_by_NID(
        subject, NID_commonName, cn_buf, sizeof(cn_buf) - 1);

    if (cn_len <= 0) {
        throw std::runtime_error("Certificate has no Common Name field");
    }

    std::string actual_cn(cn_buf, cn_len);
    if (actual_cn != expected_cn) {
        throw std::runtime_error(
            "Certificate identity mismatch: expected CN '" + expected_cn +
            "' but certificate says '" + actual_cn + "'");
    }

    // All three checks passed — cert is trusted, current, and correctly named.
}

std::string sign_challenge(EVP_PKEY* private_key, const std::string& challenge) {
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to allocate signing context");
    }

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, private_key) != 1) {
        throw std::runtime_error("EVP_DigestSignInit failed: " + openssl_last_error());
    }

    if (EVP_DigestSignUpdate(ctx.get(), challenge.data(), challenge.size()) != 1) {
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    // First call with nullptr buffer to discover the required signature length.
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal (size query) failed");
    }

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) != 1) {
        throw std::runtime_error("EVP_DigestSignFinal failed: " + openssl_last_error());
    }

    return std::string(reinterpret_cast<char*>(sig.data()), sig_len);
}

bool verify_challenge_signature(X509* cert, const std::string& challenge,
                                 const std::string& signature) {
    // Extract the public key from THIS SPECIFIC certificate — not any
    // key the caller happens to have lying around. This is what makes
    // the proof mean "whoever signed this holds cert's private key",
    // not just "someone with some valid key signed something."
    EVP_PKEY_ptr pubkey(X509_get_pubkey(cert));
    if (!pubkey) {
        throw std::runtime_error("Failed to extract public key from certificate");
    }

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to allocate verification context");
    }

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pubkey.get()) != 1) {
        throw std::runtime_error("EVP_DigestVerifyInit failed: " + openssl_last_error());
    }

    if (EVP_DigestVerifyUpdate(ctx.get(), challenge.data(), challenge.size()) != 1) {
        throw std::runtime_error("EVP_DigestVerifyUpdate failed");
    }

    // Returns 1 = valid, 0 = invalid signature, <0 = other error.
    int result = EVP_DigestVerifyFinal(
        ctx.get(),
        reinterpret_cast<const unsigned char*>(signature.data()),
        signature.size());

    return result == 1;
}
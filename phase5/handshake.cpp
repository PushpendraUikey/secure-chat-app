#include "handshake.h"
#include "net_io.h"
#include "protocol.h"
#include "pki.h"
#include "dh.h"
#include "crypto_utils.h"
#include "base64.h"

#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <stdexcept>

static std::string random_hex_nonce(size_t num_bytes) {
    std::vector<unsigned char> buf(num_bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(num_bytes)) != 1) {
        throw std::runtime_error("Failed to generate random challenge nonce");
    }
    std::ostringstream oss;
    for (unsigned char b : buf) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

bool client_perform_handshake(
    int sock,
    std::string& pending,
    const std::string& ca_cert_path,
    const std::string& expected_cn,
    std::array<unsigned char, AES_KEY_SIZE>& session_key) {

    try {
        // --- Step 1: receive and validate the server's certificate ---
        std::string line;
        if (!read_line(sock, pending, line)) {
            std::cerr << "[CLIENT] Connection closed before certificate received\n";
            return false;
        }
        if (!starts_with(line, "CERT ")) {
            std::cerr << "[CLIENT] Expected CERT, got: " << line << "\n";
            return false;
        }

        std::string cert_pem = base64_decode(line.substr(5));
        X509_ptr server_cert = certificate_from_pem(cert_pem);
        X509_ptr ca_cert = load_certificate(ca_cert_path);

        // Throws with a specific reason on ANY of the three checks
        // (signature / validity dates / CN) — caught below.
        validate_certificate(server_cert.get(), ca_cert.get(), expected_cn);

        std::cout << "[*] Server certificate validated: signature OK, "
                     "not expired, CN matches '" << expected_cn << "'\n";

        // --- Step 2: proof-of-possession challenge ---
        std::string challenge = random_hex_nonce(CHALLENGE_NONCE_BYTES);
        if (!send_line(sock, "CHALLENGE " + challenge)) {
            std::cerr << "[CLIENT] Failed to send challenge\n";
            return false;
        }

        if (!read_line(sock, pending, line)) {
            std::cerr << "[CLIENT] Connection closed before signature received\n";
            return false;
        }
        if (!starts_with(line, "SIG ")) {
            std::cerr << "[CLIENT] Expected SIG, got: " << line << "\n";
            return false;
        }

        std::string signature = base64_decode(line.substr(4));

        // Verifies using the public key embedded in the cert we JUST
        // validated — ties "holds the private key" to the same identity
        // the CA vouched for, not to any arbitrary key.
        if (!verify_challenge_signature(server_cert.get(), challenge, signature)) {
            std::cerr << "[CLIENT] Proof-of-possession FAILED — server could not "
                         "prove it holds the private key for this certificate. "
                         "Aborting.\n";
            return false;
        }

        std::cout << "[*] Server proved possession of certificate's private key.\n";

        // --- Step 3: DH exchange, identical to Phase 2 ---
        DiffieHellman dh;
        dh.generate_keypair();

        if (!send_line(sock, "DH_INIT " + dh.get_public_value_hex())) {
            return false;
        }
        if (!read_line(sock, pending, line)) {
            std::cerr << "[CLIENT] Connection closed during DH exchange\n";
            return false;
        }
        if (!starts_with(line, "DH_ACK ")) {
            std::cerr << "[CLIENT] Expected DH_ACK, got: " << line << "\n";
            return false;
        }

        std::string server_pub = line.substr(7);
        std::string shared_secret = dh.compute_shared_secret(server_pub);
        session_key = derive_key(shared_secret);

        std::cout << "[*] Secure session established.\n"
                  << "[*] Key Fingerprint: " << fingerprint(shared_secret) << "\n";

        return true;

    } catch (const std::exception& e) {
        std::cerr << "[CLIENT] Handshake aborted: " << e.what() << "\n";
        return false;
    }
}

bool server_perform_handshake(
    int sock,
    std::string& pending,
    X509* server_cert,
    EVP_PKEY* server_key,
    std::array<unsigned char, AES_KEY_SIZE>& session_key) {

    try {
        // --- Step 1: send our certificate ---
        std::string cert_pem = certificate_to_pem(server_cert);
        if (!send_line(sock, "CERT " + base64_encode(cert_pem))) {
            return false;
        }

        // --- Step 2: answer the client's challenge ---
        std::string line;
        if (!read_line(sock, pending, line)) {
            std::cerr << "[SERVER] Connection closed before challenge received\n";
            return false;
        }
        if (!starts_with(line, "CHALLENGE ")) {
            std::cerr << "[SERVER] Expected CHALLENGE, got: " << line << "\n";
            return false;
        }

        std::string challenge = line.substr(10);
        std::string signature = sign_challenge(server_key, challenge);

        if (!send_line(sock, "SIG " + base64_encode(signature))) {
            return false;
        }

        // --- Step 3: DH exchange, identical to Phase 2 ---
        if (!read_line(sock, pending, line)) {
            std::cerr << "[SERVER] Connection closed during DH exchange\n";
            return false;
        }
        if (!starts_with(line, "DH_INIT ")) {
            std::cerr << "[SERVER] Expected DH_INIT, got: " << line << "\n";
            return false;
        }

        std::string client_pub = line.substr(8);
        DiffieHellman dh;
        dh.generate_keypair();

        if (!send_line(sock, "DH_ACK " + dh.get_public_value_hex())) {
            return false;
        }

        std::string shared_secret = dh.compute_shared_secret(client_pub);
        session_key = derive_key(shared_secret);

        std::cout << "[SERVER] Handshake complete for socket " << sock << "\n"
                  << "[SERVER] Key Fingerprint: " << fingerprint(shared_secret) << "\n";

        return true;

    } catch (const std::exception& e) {
        std::cerr << "[SERVER] Handshake failed for socket " << sock << ": " << e.what() << "\n";
        return false;
    }
}
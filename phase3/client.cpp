#include "protocol.h"
#include "dh.h"
#include "crypto_utils.h"
#include "aes_gcm.h"
#include "base64.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <array>

bool send_all(int sock, const std::string& data) {
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(sock, data.data() + total_sent, data.size() - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

bool send_line(int sock, const std::string& message) {
    return send_all(sock, message + "\n");
}

bool send_secure_line(int sock, const std::array<unsigned char, AES_KEY_SIZE>& key, const std::string& message) {
    std::string blob = encrypt_message(key, message);
    std::string b64 = base64_encode(blob);
    return send_line(sock, b64);
}

void receive_messages(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& key,
    std::atomic<bool>& running
) {
    std::string pending_data;
    char buffer[BUFFER_SIZE];

    while (running) {
        ssize_t bytes_received = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            std::cout << "\n[Disconnected from server]\n";
            running = false;
            break;
        }

        pending_data.append(buffer, bytes_received);

        while (true) {
            size_t newline = pending_data.find('\n');
            if (newline == std::string::npos) break;

            std::string raw_line = pending_data.substr(0, newline);
            pending_data.erase(0, newline + 1);

            std::string line;
            try {
                line = decrypt_message(key, base64_decode(raw_line));
            } catch (const std::exception& e) {
                std::cout << "\n[CRYPTO ERROR] Tampering detected: " << e.what() << "\n> " << std::flush;
                running = false;
                break;
            }

            if (starts_with(line, "FROM ")) {
                std::string rest = line.substr(5);
                size_t space = rest.find(' ');
                if (space != std::string::npos) {
                    std::cout << "\n[" << rest.substr(0, space) << "] "
                              << rest.substr(space + 1) << "\n> " << std::flush;
                }
            }
            else if (starts_with(line, "USERS")) {
                std::cout << "\nOnline users: " << line.substr(5) << "\n> " << std::flush;
            }
            else if (starts_with(line, "ERR ")) {
                std::cout << "\n[ERROR] " << line.substr(4) << "\n> " << std::flush;
            }
            else if (starts_with(line, "OK ")) {
                std::cout << "\n[SERVER] " << line.substr(3) << "\n> " << std::flush;
            }
            else {
                std::cout << "\n[SERVER] " << line << "\n> " << std::flush;
            }
        }
    }
}

void print_help() {
    std::cout << "\nCommands:\n"
              << "  @username message  Send message and select user\n"
              << "  /chat username     Select chat partner\n"
              << "  /who               Show online users\n"
              << "  /quit              Disconnect and exit\n"
              << "\nAny other text is sent to the selected user.\n\n";
}

bool perform_dh_handshake(int sock, std::array<unsigned char, AES_KEY_SIZE>& session_key) {
    DiffieHellman dh;
    dh.generate_keypair();
    
    if (!send_line(sock, "DH_INIT " + dh.get_public_value_hex())) {
        return false;
    }

    char buffer[BUFFER_SIZE];
    std::string pending;
    
    while (true) {
        ssize_t bytes = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) return false;
        pending.append(buffer, bytes);
        
        size_t nl = pending.find('\n');
        if (nl != std::string::npos) {
            std::string line = pending.substr(0, nl);
            if (starts_with(line, "DH_ACK ")) {
                std::string server_pub = line.substr(7);
                std::string shared_secret = dh.compute_shared_secret(server_pub);
                session_key = derive_key(shared_secret);
                
                std::cout << "[*] Secure session established.\n"
                          << "[*] Key Fingerprint: " << fingerprint(shared_secret) << "\n";
                return true;
            }
            return false;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <username>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string username = argv[3];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP\n";
        close(sock);
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    std::array<unsigned char, AES_KEY_SIZE> session_key;
    if (!perform_dh_handshake(sock, session_key)) {
        std::cerr << "Diffie-Hellman handshake failed.\n";
        close(sock);
        return 1;
    }

    if (!send_secure_line(sock, session_key, "LOGIN " + username)) {
        std::cerr << "Could not send login\n";
        close(sock);
        return 1;
    }

    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, sock, std::ref(session_key), std::ref(running));

    std::string selected_user;
    std::cout << "Connected as: " << username << std::endl;
    print_help();

    while (running) {
        std::cout << "> ";
        std::string input;
        if (!std::getline(std::cin, input)) break;
        if (input.empty()) continue;

        if (input == "/who") {
            send_secure_line(sock, session_key, "WHO");
        }
        else if (input == "/quit") {
            send_secure_line(sock, session_key, "QUIT");
            running = false;
            break;
        }
        else if (starts_with(input, "/chat ")) {
            std::string target = input.substr(6);
            if (target.empty()) {
                std::cout << "Usage: /chat username\n";
                continue;
            }
            selected_user = target;
            std::cout << "Now chatting with: " << selected_user << std::endl;
        }
        else if (input[0] == '@') {
            size_t space = input.find(' ');
            if (space == std::string::npos) {
                std::cout << "Usage: @username message\n";
                continue;
            }
            std::string target = input.substr(1, space - 1);
            std::string message = input.substr(space + 1);

            if (target.empty() || message.empty()) {
                std::cout << "Usage: @username message\n";
                continue;
            }
            selected_user = target;
            send_secure_line(sock, session_key, "MSG " + selected_user + " " + message);
        }
        else {
            if (selected_user.empty()) {
                std::cout << "No chat partner selected.\n"
                          << "Use /chat username or @username message\n";
                continue;
            }
            send_secure_line(sock, session_key, "MSG " + selected_user + " " + input);
        }
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    if (receiver.joinable()) {
        receiver.join();
    }
    return 0;
}
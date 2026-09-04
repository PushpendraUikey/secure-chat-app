#include "protocol.h"
#include "dh.h"
#include "crypto_utils.h"
#include "aes_gcm.h"
#include "base64.h"
#include "pki.h"
#include "handshake.h"
#include "net_io.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <array>

void send_secure_line(int sock, const std::array<unsigned char, AES_KEY_SIZE>& key, const std::string& message) {
    send_line(sock, base64_encode(encrypt_message(key, message)));
}

void receive_messages(
    int sock,
    std::string pending,
    const std::array<unsigned char, AES_KEY_SIZE>& key,
    std::atomic<bool>& running
) {
    while (running) {
        std::string raw_line;
        if (!read_line(sock, pending, raw_line)) {
            std::cout << "\n[Disconnected from server]\n";
            running = false;
            break;
        }

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
        } else if (starts_with(line, "USERS")) {
            std::cout << "\nOnline users: " << line.substr(5) << "\n> " << std::flush;
        } else if (starts_with(line, "ERR ")) {
            std::cout << "\n[ERROR] " << line.substr(4) << "\n> " << std::flush;
        } else if (starts_with(line, "OK ")) {
            std::cout << "\n[SERVER] " << line.substr(3) << "\n> " << std::flush;
        } else {
            std::cout << "\n[SERVER] " << line << "\n> " << std::flush;
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

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <server_ip> <port> <username> <ca_cert_path> <expected_server_cn>\n"
                  << "  <expected_server_cn> must match the cert's CN — typically\n"
                  << "  the Server VM's IP, e.g. 10.0.2.15\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string username = argv[3];
    std::string ca_cert_path = argv[4];
    std::string expected_cn = argv[5];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP\n"; close(sock); return 1;
    }
    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect"); close(sock); return 1;
    }

    std::string pending;
    std::array<unsigned char, AES_KEY_SIZE> session_key;

    if (!client_perform_handshake(sock, pending, ca_cert_path, expected_cn, session_key)) {
        // Reason already printed by client_perform_handshake.
        // abort here — no LOGIN, no further data sent.
        std::cerr << "[CLIENT] Aborting connection — server could not be authenticated.\n";
        close(sock);
        return 1;
    }

    send_secure_line(sock, session_key, "LOGIN " + username);

    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, sock, std::move(pending), std::ref(session_key), std::ref(running));

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
        } else if (input == "/quit") {
            send_secure_line(sock, session_key, "QUIT");
            running = false;
            break;
        } else if (starts_with(input, "/chat ")) {
            std::string target = input.substr(6);
            if (target.empty()) { std::cout << "Usage: /chat username\n"; continue; }
            selected_user = target;
            std::cout << "Now chatting with: " << selected_user << std::endl;
        } else if (input[0] == '@') {
            size_t space = input.find(' ');
            if (space == std::string::npos) { std::cout << "Usage: @username message\n"; continue; }
            std::string target = input.substr(1, space - 1);
            std::string message = input.substr(space + 1);
            if (target.empty() || message.empty()) { std::cout << "Usage: @username message\n"; continue; }
            selected_user = target;
            send_secure_line(sock, session_key, "MSG " + selected_user + " " + message);
        } else {
            if (selected_user.empty()) {
                std::cout << "No chat partner selected.\nUse /chat username or @username message\n";
                continue;
            }
            send_secure_line(sock, session_key, "MSG " + selected_user + " " + input);
        }
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    if (receiver.joinable()) receiver.join();
    return 0;
}
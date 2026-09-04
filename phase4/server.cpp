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
#include <map>
#include <mutex>
#include <sstream>
#include <memory>
#include <array>

std::map<std::string, int> clients;
std::mutex clients_mutex;
std::map<int, std::shared_ptr<std::mutex>> client_write_mutexes;
std::map<int, std::array<unsigned char, AES_KEY_SIZE>> client_keys;

std::string get_username_by_socket(int sock) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& pair : clients) if (pair.second == sock) return pair.first;
    return "";
}

std::shared_ptr<std::mutex> get_write_mutex(int sock) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    auto it = client_write_mutexes.find(sock);
    return (it != client_write_mutexes.end()) ? it->second : nullptr;
}

void send_line_safe(int sock, const std::string& message) {
    auto mtx = get_write_mutex(sock);
    if (mtx) { std::lock_guard<std::mutex> lock(*mtx); send_line(sock, message); }
    else { send_line(sock, message); }
}

void send_secure_line_safe(int sock, const std::string& message) {
    std::array<unsigned char, AES_KEY_SIZE> key;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = client_keys.find(sock);
        if (it == client_keys.end()) return;
        key = it->second;
    }
    send_line_safe(sock, base64_encode(encrypt_message(key, message)));
}

void remove_client(int sock) {
    std::shared_ptr<std::mutex> write_mtx;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (auto it = clients.begin(); it != clients.end(); ++it) {
            if (it->second == sock) {
                std::cout << "[SERVER] User disconnected: " << it->first << std::endl;
                clients.erase(it);
                client_keys.erase(sock);
                break;
            }
        }
        auto it2 = client_write_mutexes.find(sock);
        if (it2 != client_write_mutexes.end()) {
            write_mtx = it2->second;
            client_write_mutexes.erase(it2);
        }
    }
    if (write_mtx) { std::lock_guard<std::mutex> lock(*write_mtx); close(sock); }
    else { close(sock); }
}

void handle_who(int sock) {
    std::ostringstream response;
    response << "USERS";
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (const auto& pair : clients) response << " " << pair.first;
    }
    send_secure_line_safe(sock, response.str());
}

void handle_message(int sender_sock, const std::string& recipient, const std::string& message) {
    std::string sender = get_username_by_socket(sender_sock);
    if (sender.empty()) {
        send_secure_line_safe(sender_sock, "ERR You are not logged in");
        return;
    }

    int recipient_sock = -1;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = clients.find(recipient);
        if (it != clients.end()) recipient_sock = it->second;
    }

    if (recipient_sock == -1) {
        send_secure_line_safe(sender_sock, "ERR User '" + recipient + "' is not online");
        return;
    }

    std::cout << "[RELAY PLAINTEXT] " << sender << " -> " << recipient << ": " << message << std::endl;
    send_secure_line_safe(recipient_sock, "FROM " + sender + " " + message);
    send_secure_line_safe(sender_sock, "OK Message delivered");
}

bool process_command(int sock, const std::string& line, std::string& username) {
    if (starts_with(line, "LOGIN ")) {
        if (!username.empty()) { send_secure_line_safe(sock, "ERR Already logged in"); return true; }
        std::string requested_name = line.substr(6);
        if (requested_name.empty()) { send_secure_line_safe(sock, "ERR Username cannot be empty"); return true; }
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            if (clients.count(requested_name)) {
                send_secure_line_safe(sock, "ERR Username already in use");
                return true;
            }
            clients[requested_name] = sock;
            client_write_mutexes[sock] = std::make_shared<std::mutex>();
        }
        username = requested_name;
        std::cout << "[SERVER] User connected: " << username << std::endl;
        send_secure_line_safe(sock, "OK Logged in as " + username);
        return true;
    }

    if (username.empty()) { send_secure_line_safe(sock, "ERR Please LOGIN first"); return true; }

    if (line == "WHO") { handle_who(sock); return true; }

    if (starts_with(line, "MSG ")) {
        std::string rest = line.substr(4);
        size_t space = rest.find(' ');
        if (space == std::string::npos) {
            send_secure_line_safe(sock, "ERR Usage: MSG <username> <message>");
            return true;
        }
        std::string recipient = rest.substr(0, space);
        std::string message = rest.substr(space + 1);
        if (message.empty()) { send_secure_line_safe(sock, "ERR Message cannot be empty"); return true; }
        handle_message(sock, recipient, message);
        return true;
    }

    if (line == "QUIT") { send_secure_line_safe(sock, "OK Goodbye"); return false; }

    send_secure_line_safe(sock, "ERR Unknown command");
    return true;
}

void handle_client(int client_sock, X509* server_cert, EVP_PKEY* server_key) {
    std::string pending;
    std::array<unsigned char, AES_KEY_SIZE> session_key;

    if (!server_perform_handshake(client_sock, pending, server_cert, server_key, session_key)) {
        std::cerr << "[SERVER] Handshake failed/aborted for socket " << client_sock << "\n";
        close(client_sock);
        return;
    }

    { std::lock_guard<std::mutex> lock(clients_mutex); client_keys[client_sock] = session_key; }

    std::string username;

    while (true) {
        std::string raw_line;
        if (!read_line(client_sock, pending, raw_line)) break;

        std::string line;
        try {
            line = decrypt_message(session_key, base64_decode(raw_line));
        } catch (const std::exception& e) {
            std::cerr << "[SERVER] Crypto error on socket " << client_sock << ": " << e.what() << "\n";
            try { send_secure_line_safe(client_sock, "ERR Message authentication failed - connection terminated"); }
            catch (...) {}
            remove_client(client_sock);
            return;
        }

        if (!process_command(client_sock, line, username)) {
            remove_client(client_sock);
            return;
        }
    }
    remove_client(client_sock);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <port> <server_cert.pem> <server_key.pem>\n";
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string cert_path = argv[2];
    std::string key_path = argv[3];

    X509_ptr server_cert;
    EVP_PKEY_ptr server_key;
    try {
        server_cert = load_certificate(cert_path);
        server_key = load_private_key(key_path);
    } catch (const std::exception& e) {
        std::cerr << "[SERVER] Failed to load certificate/key: " << e.what() << "\n";
        return 1;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("bind"); close(server_sock); return 1;
    }
    if (listen(server_sock, 10) < 0) { perror("listen"); close(server_sock); return 1; }

    std::cout << "====================================\n"
              << " Secure Chat - Phase 3 Server\n"
              << " PKI-Authenticated Encrypted TCP Chat\n"
              << " Listening on port " << port << "\n"
              << "====================================\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_sock < 0) { perror("accept"); continue; }

        std::cout << "[SERVER] New TCP connection from " << inet_ntoa(client_addr.sin_addr) << std::endl;

        // server_cert/server_key are loaded once and never mutated after —
        // safe to share raw pointers read-only across all connection
        // threads (each thread's own EVP_MD_CTX in sign_challenge/
        // verify_challenge_signature keeps concurrent uses independent).
        std::thread(handle_client, client_sock, server_cert.get(), server_key.get()).detach();
    }

    close(server_sock);
    return 0;
}
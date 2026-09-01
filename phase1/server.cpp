#include "protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <iostream>
#include <thread>
#include <string>
#include <map>
#include <mutex>


std::map<std::string, int> clients;
std::mutex clients_mutex;

std::string get_username_by_socket(int sock) {
    std::lock_guard<std::mutex> lock(clients_mutex);

    for (const auto& pair : clients) {
        if (pair.second == sock) {
            return pair.first;
        }
    }

    return "";
}

bool process_command(
    int sock,
    const std::string& line,
    std::string& username
) {
    if (starts_with(line, "LOGIN ")) {
        if (!username.empty()) {
            return true;
        }

        std::string requested_name = line.substr(6);

        if (requested_name.empty()) {
            return true;
        }

        {
            std::lock_guard<std::mutex> lock(clients_mutex);

            if (clients.count(requested_name)) {
                return true;
            }

            clients[requested_name] = sock;
        }

        username = requested_name;

        std::cout << "[SERVER] User connected: "
                  << username << std::endl;


        return true;
    }
    return false;
}

void handle_client(int client_sock) {
    std::string username;
    std::string pending_data;

    char buffer[BUFFER_SIZE];

    while (true) {
        ssize_t bytes_received = recv(
            client_sock,
            buffer,
            sizeof(buffer),
            0
        );

        if (bytes_received <= 0) {
            break;
        }

        pending_data.append(buffer, bytes_received);

        while (true) {
            size_t newline = pending_data.find('\n');

            if (newline == std::string::npos) {
                break;
            }

            std::string line =
                pending_data.substr(0, newline);

            pending_data.erase(0, newline + 1);

            process_command(
                client_sock,
                line,
                username
            );
        }
    }

}

int main(int argc, char* argv[]) {
    int port = CHAT_PORT;

    if (argc == 2) {
        port = std::stoi(argv[1]);
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (server_sock < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;

    setsockopt(
        server_sock,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt)
    );

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(
            server_sock,
            reinterpret_cast<sockaddr*>(&server_addr),
            sizeof(server_addr)
        ) < 0) {

        perror("bind");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 10) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }

    std::cout << "====================================\n";
    std::cout << " Secure Chat - Phase 1 Server\n";
    std::cout << " Plaintext TCP Chat\n";
    std::cout << " Listening on port " << port << "\n";
    std::cout << "====================================\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(
            server_sock,
            reinterpret_cast<sockaddr*>(&client_addr),
            &client_len
        );

        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        std::cout << "[SERVER] New TCP connection from "
                  << inet_ntoa(client_addr.sin_addr)
                  << std::endl;

        std::thread(
            handle_client,
            client_sock
        ).detach();
    }

    close(server_sock);

    return 0;
}
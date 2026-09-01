#include "protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

bool send_all(int sock, const std::string& data) {
    size_t total_sent = 0;

    while (total_sent < data.size()) {
        ssize_t sent = send(
            sock,
            data.data() + total_sent,
            data.size() - total_sent,
            0
        );

        if (sent <= 0) {
            return false;
        }

        total_sent += static_cast<size_t>(sent);
    }

    return true;
}

bool send_line(int sock, const std::string& message) {
    return send_all(sock, message + "\n");
}

void receive_messages(
    int sock,
    std::atomic<bool>& running
) {
    std::string pending_data;

    char buffer[BUFFER_SIZE];

    while (running) {
        ssize_t bytes_received = recv(
            sock,
            buffer,
            sizeof(buffer),
            0
        );

        if (bytes_received <= 0) {
            std::cout
                << "\n[Disconnected from server]\n";

            running = false;
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

            if (starts_with(line, "FROM ")) {
                std::string rest = line.substr(5);

                size_t space = rest.find(' ');

                if (space != std::string::npos) {
                    std::string sender =
                        rest.substr(0, space);

                    std::string message =
                        rest.substr(space + 1);

                    std::cout
                        << "\n[" << sender << "] "
                        << message << "\n> "
                        << std::flush;
                }
            }
            else if (starts_with(line, "USERS")) {
                std::cout
                    << "\nOnline users: "
                    << line.substr(5)
                    << "\n> "
                    << std::flush;
            }
            else if (starts_with(line, "ERR ")) {
                std::cout
                    << "\n[ERROR] "
                    << line.substr(4)
                    << "\n> "
                    << std::flush;
            }
            else if (starts_with(line, "OK ")) {
                std::cout
                    << "\n[SERVER] "
                    << line.substr(3)
                    << "\n> "
                    << std::flush;
            }
            else {
                std::cout
                    << "\n[SERVER] "
                    << line
                    << "\n> "
                    << std::flush;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr
            << "Usage: "
            << argv[0]
            << " <server_ip> <port> <username>\n";

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

    if (inet_pton(
            AF_INET,
            server_ip.c_str(),
            &server_addr.sin_addr
        ) <= 0) {

        std::cerr << "Invalid server IP\n";
        close(sock);
        return 1;
    }

    if (connect(
            sock,
            reinterpret_cast<sockaddr*>(&server_addr),
            sizeof(server_addr)
        ) < 0) {

        perror("connect");
        close(sock);
        return 1;
    }

    if (!send_line(sock, "LOGIN " + username)) {
        std::cerr << "Could not send login\n";
        close(sock);
        return 1;
    }

    std::atomic<bool> running(true);

    std::thread receiver(
        receive_messages,
        sock,
        std::ref(running)
    );

    std::string selected_user;

    std::cout
        << "Connected as: "
        << username
        << std::endl;

    shutdown(sock, SHUT_RDWR);

    close(sock);

    if (receiver.joinable()) {
        receiver.join();
    }

    return 0;
}
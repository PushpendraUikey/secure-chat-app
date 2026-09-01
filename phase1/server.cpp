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
#include <sstream>


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

void send_line(int sock, const std::string& message) {
    send_all(sock, message + "\n");
}

void handle_who(int sock) {
    std::ostringstream response;
    response << "USERS";

    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        for (const auto& pair : clients) {
            response << " " << pair.first;
        }
    }

    send_line(sock, response.str());
}

void handle_message(
    int sender_sock,
    const std::string& recipient,
    const std::string& message
) {
    std::string sender = get_username_by_socket(sender_sock);

    if (sender.empty()) {
        send_line(sender_sock, "ERR You are not logged in");
        return;
    }

    int recipient_sock = -1;

    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        auto it = clients.find(recipient);

        if (it != clients.end()) {
            recipient_sock = it->second;
        }
    }

    if (recipient_sock == -1) {
        send_line(
            sender_sock,
            "ERR User '" + recipient + "' is not online"
        );
        return;
    }

    // IMPORTANT: Phase 1 verification requirement.
    // The server can read the complete plaintext message.
    std::cout << "[RELAY PLAINTEXT] "
              << sender << " -> "
              << recipient << ": "
              << message
              << std::endl;

    send_line(
        recipient_sock,
        "FROM " + sender + " " + message
    );

    send_line(sender_sock, "OK Message delivered");
}

bool process_command(
    int sock,
    const std::string& line,
    std::string& username
) {
    if (starts_with(line, "LOGIN ")) {
        if (!username.empty()) {
            send_line(sock, "ERR Already logged in");
            return true;
        }

        std::string requested_name = line.substr(6);

        if (requested_name.empty()) {
            send_line(sock, "ERR Username cannot be empty");
            return true;
        }

        {
            std::lock_guard<std::mutex> lock(clients_mutex);

            if (clients.count(requested_name)) {
                send_line(sock, "ERR Username already in use");
                return true;
            }

            clients[requested_name] = sock;
        }

        username = requested_name;

        std::cout << "[SERVER] User connected: "
                  << username << std::endl;

        send_line(sock, "OK Logged in as " + username);

        return true;
    }

    if (username.empty()) {
        send_line(sock, "ERR Please LOGIN first");
        return true;
    }

    if (line == "WHO") {
        handle_who(sock);
        return true;
    }

    if (starts_with(line, "MSG ")) {
        std::string rest = line.substr(4);

        size_t space = rest.find(' ');

        if (space == std::string::npos) {
            send_line(
                sock,
                "ERR Usage: MSG <username> <message>"
            );
            return true;
        }

        std::string recipient = rest.substr(0, space);
        std::string message = rest.substr(space + 1);

        if (message.empty()) {
            send_line(sock, "ERR Message cannot be empty");
            return true;
        }

        handle_message(sock, recipient, message);

        return true;
    }

    send_line(sock, "ERR Unknown command");

    return true;
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
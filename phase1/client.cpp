#include "protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <csignal>

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

void print_help() {
    std::cout << "\nCommands:\n";
    std::cout << "  @username message  Send message and select user\n";
    std::cout << "  /chat username     Select chat partner\n";
    std::cout << "  /who               Show online users\n";
    std::cout << "  /quit              Disconnect and exit\n";
    std::cout << "\nAny other text is sent to the selected user.\n\n";
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <username>\n";
        return 1;
    }

    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to prevent crashes on write to closed sockets

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

    if (!send_line(sock, "LOGIN " + username)) {
        std::cerr << "Could not send login\n";
        close(sock);
        return 1;
    }

    std::cout << "Connected as: " << username << std::endl;
    print_help();
    std::cout << "> " << std::flush;

    std::string selected_user;
    std::string pending_sock_data;
    std::string pending_stdin_data;

    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = sock;
    fds[1].events = POLLIN;

    bool running = true;
    while (running) {
        int ret = poll(fds, 2, -1); // block indefinitely until one FD is ready
        if( ret < 0 ) {
            perror("poll");
            break;
        }

        // 1. Handle incoming SERVER data
        if( fds[1].revents & (POLLIN | POLLERR | POLLHUP) ) {
            char buffer[BUFFER_SIZE];
            ssize_t bytes_received = recv(sock, buffer, sizeof(buffer), 0);

            if( bytes_received <= 0 ) {
                std::cerr << "\n[Disconnected from server]\n";
                running = false;
                break;
            }

            pending_sock_data.append(buffer, bytes_received);

            while(true) {
                size_t newline = pending_sock_data.find('\n');
                if( newline == std::string::npos )  break;

                std::string line = pending_sock_data.substr(0, newline);
                pending_sock_data.erase(0, newline + 1);

                // Clean up carriage return from telnet/netcat testing
                if(!line.empty() && line.back() == '\r') line.pop_back();

                if (starts_with(line, "FROM ")) {
                    std::string rest = line.substr(5);
                    size_t space = rest.find(' ');

                    if (space != std::string::npos) {
                        std::string sender = rest.substr(0, space);
                        std::string message =rest.substr(space + 1);

                        std::cout << "\n[" << sender << "] " << message << "\n> " << std::flush;
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

        // 2. Handle user KEYBOARD input
        if( fds[0].revents & POLLIN) {
            char buffer[BUFFER_SIZE];
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));

            if( bytes_read <= 0 ) break;    // EOF on stdin

            pending_stdin_data.append(buffer, bytes_read);

            while(true) {
                size_t newline = pending_stdin_data.find('\n');
                if( newline == std::string::npos ) break;

                std::string input = pending_stdin_data.substr(0, newline);
                pending_stdin_data.erase(0, newline + 1);

                if(input.empty()) {
                    std::cout << "> " << std::flush;
                    continue;
                }
                
                if (input == "/who") {
                    send_line(sock, "WHO");
                }

                else if (input == "/quit") {
                    send_line(sock, "QUIT");
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

                    std::cout
                        << "Now chatting with: "
                        << selected_user
                        << std::endl;
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
                    send_line(sock, "MSG " + selected_user + " " + message);
                }

                else {
                    if (selected_user.empty()) {
                        std::cout
                            << "No chat partner selected.\n"
                            << "Use /chat username or "
                            << "@username message\n";
                        continue;
                    }

                    send_line(sock, "MSG " + selected_user + " " + input);
                }
            }
        }  
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);

    return 0;
}
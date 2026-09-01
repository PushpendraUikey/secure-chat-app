#include "protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>


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

    }

    close(server_sock);

    return 0;
}
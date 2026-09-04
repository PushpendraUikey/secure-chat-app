#include "net_io.h"
#include "protocol.h"
#include <sys/socket.h>
#include <iostream>

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

bool read_line(int sock, std::string& pending, std::string& out_line) {
    while (true) {
        size_t nl = pending.find('\n');
        if (nl != std::string::npos) {
            // Reject any single line — even one that DOES eventually
            // terminate — that grew past the cap before we found the
            // newline. A well-formed peer never needs a line this long
            // (largest legitimate payload is a base64 cert, comfortably
            // under 16KB for a 2048-bit RSA cert).
            if (nl > MAX_LINE_LENGTH) {
                std::cerr << "[net_io] Line exceeded " << MAX_LINE_LENGTH
                          << " bytes before newline — dropping connection\n";
                return false;
            }
            out_line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            return true;
        }

        // No newline yet — before reading more, check whether what
        // we've already buffered has blown past the cap. This catches
        // the actual DoS case: a peer streaming endless bytes with no
        // '\n' at all, which would otherwise grow `pending` forever.
        if (pending.size() > MAX_LINE_LENGTH) {
            std::cerr << "[net_io] Unterminated input exceeded " << MAX_LINE_LENGTH
                       << " bytes — dropping connection\n";
            return false;
        }

        char buffer[BUFFER_SIZE];
        ssize_t bytes = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) return false;
        pending.append(buffer, bytes);
    }
}
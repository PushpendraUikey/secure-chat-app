#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>

// One complete application message = one line terminated by '\n'.
//
// Client -> Server
//   LOGIN <username>
//   WHO
//   MSG <recipient> <message>
//   QUIT
//
// Server -> Client
//   OK <message>
//   ERR <message>
//   USERS <user1> <user2> ...
//   FROM <sender> <message>

constexpr int CHAT_PORT = 5000;
constexpr int BUFFER_SIZE = 4096;

inline bool starts_with(const std::string& text,
                        const std::string& prefix) {
    return text.rfind(prefix, 0) == 0;
}

#endif
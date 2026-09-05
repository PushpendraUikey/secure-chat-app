#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>

// Pre-encryption handshake (in order, before any DH exchange):
//   Server -> Client: CERT <base64 PEM certificate>
//   [Client validates: signature vs CA, validity dates, CN match.
//    ANY failure -> client aborts here, sends nothing further.]
//   Client -> Server: CHALLENGE <hex nonce>
//   Server -> Client: SIG <base64 signature over challenge, using server's private key>
//   [Client verifies signature against the cert's public key. Failure -> abort.]
//   Client -> Server: DH_INIT <hex g^a mod p>
//   Server -> Client: DH_ACK <hex g^b mod p>
//   [Both derive session key via SHA-256(shared secret); all further lines encrypted.]
//
// Encrypted application layer (base64(AES-256-GCM(...)) per line), from Phase 2:
//   Client -> Server: LOGIN <username> | WHO | MSG <recipient> <message> | QUIT
//   Server -> Client: OK <message> | ERR <message> | USERS <user1> ... | FROM <sender> <message>

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
constexpr size_t CHALLENGE_NONCE_BYTES = 32;

inline bool starts_with(const std::string& text,
                        const std::string& prefix) {
    return text.rfind(prefix, 0) == 0;
}

#endif
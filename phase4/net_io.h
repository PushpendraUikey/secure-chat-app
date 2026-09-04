#ifndef NET_IO_H
#define NET_IO_H

#include <string>

constexpr size_t MAX_LINE_LENGTH = 16 * 1024; // 16KB — cap against unbounded growth

bool send_all(int sock, const std::string& data);
bool send_line(int sock, const std::string& message);

// Reads one '\n'-terminated line, buffering leftover bytes in `pending`
// across calls. Callers MUST reuse the SAME `pending` string across every
// call on a given socket — across the cert exchange, the DH exchange, and
// into the main application loop.
//
// Returns false if the peer disconnects, OR if `pending` exceeds
// MAX_LINE_LENGTH before a newline is found — the latter is treated as
// an abusive/malformed peer and the caller should close the connection.
bool read_line(int sock, std::string& pending, std::string& out_line);

#endif
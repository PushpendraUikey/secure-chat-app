# Phase 2 — Client-Server Confidentiality via Diffie-Hellman

Encrypted TCP chat: each client performs an independent Diffie-Hellman
key exchange (RFC 3526 Group 14, implemented from scratch on top of
OpenSSL's BIGNUM primitives) with the server, derives an AES-256-GCM
session key via SHA-256, and encrypts all further traffic — including
the LOGIN step — under that key.

## Build

Requires OpenSSL dev headers (`libssl-dev`) and a C++17 compiler.

```bash
cd phase2
make
```

Produces two binaries: `server` and `client`.

## Run

Start the server first (defaults to port 5000):
```bash
./server [port]
```

Then connect one or more clients:
```bash
./client <server_ip> <port> <username>
```

Example, on a LAN/VirtualBox network:
```bash
# Server VM
./server 5000

# Client VM 1
./client 10.0.2.15 5000 alice

# Client VM 2
./client 10.0.2.15 5000 bob
```

## Client commands

| Command | Effect |
|---|---|
| `@username message` | Send `message` to `username`, select them as current chat partner |
| `/chat username` | Switch current chat partner without sending a message |
| `/who` | List currently online users |
| `/quit` | Disconnect cleanly |
| *(anything else)* | Sent as a message to the currently selected partner |

## Verifying the phase's requirements

- **Fingerprint match**: both `client` and `server` print a key fingerprint
  (`[*] Key Fingerprint: ...`) right after the DH handshake completes.
  Confirm both sides show the identical value for a given connection.
- **Wireshark**: capture on the relevant interface/port, "Follow → TCP
  Stream" — content should now show base64-encoded ciphertext, not
  plaintext (contrast with Phase 1's capture).
- **Tamper detection**: flip a byte in a captured ciphertext blob and
  feed it back through `decrypt_message` — confirm it throws
  (`GCM authentication failed`) rather than producing corrupted plaintext.

## MITM attack demo (`mitm.cpp`)

Build target `proxy` (see Makefile) sits between a client and this
server, performing two independent DH exchanges — one posing as the
server to the victim client, one posing as the client to the real
server — and logs every message it can read in between.

```bash
# On Mallory VM, after building:
./proxy <real_server_ip> <real_server_port>

# On the victim Client VM — manually point it at Mallory instead of
# the real server:
./client <mallory_ip> 5001 alice
```

Confirm the proxy's terminal shows `[MITM INTERCEPT ...]` lines with
full plaintext, even though both the client and server believe they're
talking directly and securely to each other.
# Phase 3 — Server Authentication via PKI

Extends Phase 2 with a Certificate Authority, server certificate
issuance, and a pre-DH handshake in which the client validates the
server's certificate and confirms the server actually holds the
matching private key (proof-of-possession) before any key exchange or
application data is sent.

## Build

Requires OpenSSL dev headers (`libssl-dev`) and a C++17 compiler.

```bash
cd phase3
make
```

Produces `server`, `client`, and `proxy` (the updated MITM re-attempt
tool).

## One-time CA and certificate setup

```bash
cd ca
chmod +x setup_ca.sh issue_server_cert.sh

./setup_ca.sh
./issue_server_cert.sh <server_vm_ip>   # e.g. 10.0.2.15 — must match
                                          # what clients pass as expected_cn
```

This produces:
- `ca.key`, `ca.crt` — the CA's private key and self-signed root cert
- `server.key`, `server.crt` — the server's private key and CA-signed cert

**Distribute:**
- `ca.crt` → copy to every Client VM (this is the trusted root clients validate against)
- `server.key`, `server.crt` → stay on the Server VM only
- `ca.key` → stays on the Server VM only, never distributed

```bash
# from a Client VM
scp puikey@<server_ip>:~/.../phase3/ca/ca.crt ~/secure-chat/phase3/ca/
```

## Run

```bash
# Server VM
./server <port> ca/server.crt ca/server.key

# Each Client VM
./client <server_ip> <port> <username> <ca_cert_path> <expected_server_cn>
```

Example:
```bash
# Server VM
./server 5000 ca/server.crt ca/server.key

# Client VM 1
./client 10.0.2.15 5000 alice ca/ca.crt 10.0.2.15

# Client VM 2
./client 10.0.2.15 5000 bob ca/ca.crt 10.0.2.15
```

`<expected_server_cn>` must exactly match the CN baked into
`server.crt` (i.e. whatever IP/name you passed to
`issue_server_cert.sh`) — a mismatch causes the client to correctly
reject the connection at the identity-check step.

## Client commands

Same as Phase 2 — see that phase's README.

## Handshake sequence (before any application data)

1. Server sends its certificate (`CERT ...`)
2. Client validates: CA signature, validity dates, CN match — aborts
   immediately on any failure, sending nothing further
3. Client sends a random challenge (`CHALLENGE ...`)
4. Server signs it with its private key and responds (`SIG ...`)
5. Client verifies the signature against the certificate's public key —
   proves the server holds the matching private key, not just a copy
   of the cert file
6. Standard DH exchange proceeds (`DH_INIT` / `DH_ACK`), same as Phase 2

## Verifying the phase's requirements

- **Legitimate flow**: confirm both fingerprints print and match, cert
  validation messages appear on the client (`[*] Server certificate
  validated...`, `[*] Server proved possession...`), chat works.
- **MITM re-attempt** (`proxy.cpp`): run the same tool as Phase 2 against
  this server — confirm it now fails, since Mallory has no CA-signed
  certificate to present. See inline comments in `proxy.cpp` for exactly
  where/how it fails.
- **Proof-of-possession bypass test**: copy only `server.crt` (not
  `server.key`) to Mallory, attempt to serve it from a standalone
  listener, and confirm the client's challenge/signature step rejects
  it — Mallory can present the valid certificate file but cannot
  produce a valid signature without the private key.
# Secure Chat App

**CS6008 Network Security, IIT Bombay (Autumn 2026). Team of 2: Akshit Kumar, Pushpendra Uikey.**

A multithreaded TCP chat server and client in C++, taken from plaintext to authenticated end-to-end encryption in five phases. Each phase adds one defense and checks it against an attacker built in the previous one.

| Phase | Adds | Attack it answers |
|---|---|---|
| 1 | Multithreaded TCP chat server and client, plaintext | baseline |
| 2 | Diffie-Hellman key exchange and AES-GCM encryption | passive eavesdropping; a MITM proxy (`mitm.cpp`) shows it is still open to active attack |
| 3 | Private CA, server certificates, and a signed proof-of-possession challenge before key exchange | the MITM proxy is now rejected |
| 4 | Client-to-client end-to-end encryption, keyed by a per-pair DH handshake relayed through the server | a curious or compromised relay |
| 5 | Automatic E2E rekeying every 60 s for forward secrecy | later compromise of a session key |

## Build

Needs OpenSSL dev headers (`libssl-dev`) and a C++17 compiler.

```bash
cd phase5
make
```

Each `phaseN/` folder has its own README with setup and run steps (CA setup lives in `phaseN/ca/`).

## Repo layout

- `phase1/` … `phase5/`: one self-contained version per phase
- `report.pdf`: design and analysis report
- `CS6008_AS1_Secure_Chat_Assignment.pdf`: assignment statement

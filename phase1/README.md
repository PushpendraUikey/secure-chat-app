# Secure Chat Application - Phase 1

## Overview

This project is a one-to-one chat application built over TCP sockets. It serves as the foundational Phase 1 of a progressively hardened secure chat protocol. In this initial phase, the application operates in plaintext to establish the core client-server architecture, message routing, and user interface mechanics before cryptographic protections are introduced in subsequent phases.

## Goals Achieved

* **Client-Server Architecture:** Reliable TCP socket communication using POSIX standards.

* **Concurrency:** A multithreaded server capable of handling multiple client connections simultaneously with thread-safe state management.

* **Asynchronous Client I/O:** Responsive command-line interface utilizing `poll()` to handle simultaneous user keyboard input and incoming server messages without deadlocking.

* **Custom Chat Protocol:** A robust, newline-delimited application-layer protocol for handling logins, message routing, and server responses.

* **Server Relay Logging:** The server logs the full plaintext of relayed messages to verify correct routing and demonstrate the baseline lack of encryption.

## Prerequisites

* C++17 compatible compiler (e.g., `g++`)

* POSIX-compliant operating system (Linux/Ubuntu recommended)

* `make` utility

## Building the Project

A `Makefile` is provided to compile both the client and server applications. Run the following command in the project directory:

```
make

```

This will generate two executable files: `server` and `client`.

To clean up the compiled binaries:

```
make clean

```

## How to Run

### 1. Start the Server

Run the server executable. By default, it listens on port `5000`. You can optionally specify a custom port.

```
# Default port (5000)
./server

# Custom port
./server 8080

```

### 2. Connect a Client

Run the client executable, providing the server's IP address, the port number, and your desired username.

```
./client <server_ip> <port> <username>

# Example (local testing):
./client 127.0.0.1 5000 Alice

```

## Client Commands

Once connected, the client supports a simple tag-based command interface typed directly into the prompt:

| **Command** | **Description** | 
| `@username message` | Sends a message to the specified user and sets them as your active chat partner. | 
| `/chat username` | Switches your currently selected chat partner to the specified user without sending a message. | 
| `/who` | Requests and displays a list of all currently online users from the server. | 
| `/quit` | Cleanly disconnects from the server and exits the application. | 

Any standard text entered that does not start with a command tag will be sent directly to your currently selected chat partner.
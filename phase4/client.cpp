#include "protocol.h"
#include "dh.h"
#include "crypto_utils.h"
#include "aes_gcm.h"
#include "base64.h"
#include "pki.h"
#include "handshake.h"
#include "net_io.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <array>
#include <map>
#include <mutex>
#include <memory>

// Wire-level tag conventions
const std::string TAG_E2E_INIT = "__E2E_INIT__";
const std::string TAG_E2E_ACK  = "__E2E_ACK__";
const std::string TAG_E2E_MSG  = "__E2E_MSG__";

// E2E session state, guarded by e2e_mutex throughout.
std::map<std::string, std::array<unsigned char, AES_KEY_SIZE>> e2e_keys;
std::map<std::string, std::shared_ptr<DiffieHellman>> pending_dh;
std::mutex e2e_mutex;

// Serializes writes to the server socket across the main thread and
// the receiver thread (both can call send_secure_line concurrently —
// e.g. main() sending a chat message while receive_messages() is
// mid-way through replying to an incoming E2E handshake step).
std::mutex send_mutex;

bool send_secure_line(int sock, const std::array<unsigned char, AES_KEY_SIZE>& key, const std::string& message) {
    std::string blob = encrypt_message(key, message);
    std::string b64 = base64_encode(blob);
    std::lock_guard<std::mutex> lock(send_mutex);
    return send_line(sock, b64);
}

void send_chat_message(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    const std::string& target,
    const std::string& text
) {
    std::array<unsigned char, AES_KEY_SIZE> peer_key;
    bool has_e2e = false;
    bool is_pending = false;

    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        auto it = e2e_keys.find(target);
        if (it != e2e_keys.end()) {
            peer_key = it->second;
            has_e2e = true;
        } else if (pending_dh.count(target)) {
            is_pending = true;
        }
    }

    if (has_e2e) {
        std::string inner_blob = encrypt_message(peer_key, text);
        std::string inner_b64 = base64_encode(inner_blob);
        send_secure_line(sock, server_key, "MSG " + target + " " + TAG_E2E_MSG + inner_b64);
        return;
    }

    if (is_pending) {
        std::cout << "[*] E2E handshake with " << target
                  << " still in progress — this message is going through "
                     "the outer client-server tunnel only (visible to the "
                     "server), not yet end-to-end encrypted.\n";
    }

    send_secure_line(sock, server_key, "MSG " + target + " " + text);
}

void initiate_e2e(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    const std::string& target
) {
    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        if (e2e_keys.count(target)) {
            std::cout << "[*] Already have an established E2E session with "
                      << target << " — not re-initiating.\n";
            return;
        }
        if (pending_dh.count(target)) {
            std::cout << "[*] E2E handshake with " << target
                      << " is already in progress — not sending a second request.\n";
            return;
        }
    }

    auto dh = std::make_shared<DiffieHellman>();
    dh->generate_keypair();
    std::string pub_hex = dh->get_public_value_hex();

    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        // Re-check under lock in case a peer's INIT for this same target
        // arrived and got processed between our check above and now —
        // extremely unlikely given how fast this runs, but cheap to guard.
        if (pending_dh.count(target) || e2e_keys.count(target)) {
            std::cout << "[*] E2E session with " << target
                      << " was just established/started concurrently — not sending.\n";
            return;
        }
        pending_dh[target] = dh;
    }

    send_secure_line(sock, server_key, "MSG " + target + " " + TAG_E2E_INIT + pub_hex);
    std::cout << "[*] Sent E2E key exchange request to " << target << "...\n";
}

void handle_incoming_message(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    const std::string& sender,
    const std::string& payload
) {
    // --- 1. Handshake initiation from peer ---
    if (starts_with(payload, TAG_E2E_INIT)) {
        std::string peer_pub_hex = payload.substr(TAG_E2E_INIT.size());

        std::shared_ptr<DiffieHellman> dh;
        bool reusing_existing = false;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = pending_dh.find(sender);
            if (it != pending_dh.end()) {
                // SIMULTANEOUS-INITIATION CASE: we also started a
                // handshake with this exact peer before their INIT
                // arrived. Reuse OUR already-generated keypair rather
                // than manufacturing a second one — DH's shared secret
                // is symmetric (peer_pub^our_priv == our_pub^peer_priv
                // mod p), so both sides converge on the identical key
                // as long as each side commits to a single keypair per
                // peer, with no extra coordination or tie-break needed.
                dh = it->second;
                reusing_existing = true;
            } else {
                // Normal case, OR peer is re-initiating a session we
                // already consider established (e.g. their client
                // restarted and lost state). We honor it as a rekey —
                // documented simplification for Phase 4; fully
                // atomic, collision-free rekeying is Phase 5's job.
                dh = std::make_shared<DiffieHellman>();
                dh->generate_keypair();
            }
        }

        try {
            std::string our_pub_hex = dh->get_public_value_hex();
            std::string shared_secret = dh->compute_shared_secret(peer_pub_hex);
            auto key = derive_key(shared_secret);

            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                e2e_keys[sender] = key;
                if (reusing_existing) {
                    pending_dh.erase(sender); // consumed by this path now
                }
            }

            std::cout << "\n[*] End-to-End session established with " << sender << "\n";
            std::cout << "[*] E2E Key Fingerprint: " << fingerprint(shared_secret) << "\n> " << std::flush;

            // Reply with an ACK carrying our public value — the peer's
            // ACK-handler treats this as a normal completion, or (if
            // they also hit the reuse path) as a harmless duplicate.
            send_secure_line(sock, server_key, "MSG " + sender + " " + TAG_E2E_ACK + our_pub_hex);
        } catch (const std::exception& e) {
            std::cout << "\n[!] Failed to complete E2E INIT from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    // --- 2. Handshake acknowledgment from peer ---
    else if (starts_with(payload, TAG_E2E_ACK)) {
        std::string peer_pub_hex = payload.substr(TAG_E2E_ACK.size());

        std::shared_ptr<DiffieHellman> dh;
        bool already_established = false;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = pending_dh.find(sender);
            if (it != pending_dh.end()) {
                dh = it->second;
                pending_dh.erase(it);
            } else if (e2e_keys.count(sender)) {
                // A duplicate/redundant ACK — most likely the tail end
                // of a simultaneous-initiation race that already
                // resolved via the INIT-reuse path above. Not an error.
                already_established = true;
            }
        }

        if (already_established) {
            // Quiet — this is expected traffic in the race scenario,
            return;
        }

        if (!dh) {
            std::cout << "\n[!] Received unexpected E2E ACK from " << sender
                      << " (no handshake was pending) — ignoring.\n> " << std::flush;
            return;
        }

        try {
            std::string shared_secret = dh->compute_shared_secret(peer_pub_hex);
            auto key = derive_key(shared_secret);

            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                e2e_keys[sender] = key;
            }

            std::cout << "\n[*] End-to-End session established with " << sender << "\n";
            std::cout << "[*] E2E Key Fingerprint: " << fingerprint(shared_secret) << "\n> " << std::flush;
        } catch (const std::exception& e) {
            std::cout << "\n[!] Failed to complete E2E ACK from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    // --- 3. Inner-layer encrypted chat message ---
    else if (starts_with(payload, TAG_E2E_MSG)) {
        std::string inner_b64 = payload.substr(TAG_E2E_MSG.size());
        std::array<unsigned char, AES_KEY_SIZE> peer_key;
        bool has_key = false;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = e2e_keys.find(sender);
            if (it != e2e_keys.end()) {
                peer_key = it->second;
                has_key = true;
            }
        }

        if (!has_key) {
            std::cout << "\n[!] Received encrypted message from " << sender
                      << " but no E2E key is established. Run /e2e " << sender << "\n> " << std::flush;
            return;
        }

        try {
            std::string inner_blob = base64_decode(inner_b64);
            std::string plaintext = decrypt_message(peer_key, inner_blob);
            std::cout << "\n[" << sender << " (E2E)] " << plaintext << "\n> " << std::flush;
        } catch (const std::exception& e) {
            std::cout << "\n[CRYPTO ERROR] E2E Decryption/Tamper failure from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    // --- 4. Plain message (pre-E2E, or a peer choosing not to use E2E) ---
    else {
        std::cout << "\n[" << sender << "] " << payload << "\n> " << std::flush;
    }
}

void receive_messages(
    int sock,
    std::string pending,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    std::atomic<bool>& running
) {
    while (running) {
        std::string raw_line;
        if (!read_line(sock, pending, raw_line)) {
            std::cout << "\n[Disconnected from server]\n";
            running = false;
            break;
        }

        std::string line;
        try {
            line = decrypt_message(server_key, base64_decode(raw_line));
        } catch (const std::exception& e) {
            std::cout << "\n[CRYPTO ERROR] Tampering detected on client-server link: " << e.what() << "\n> " << std::flush;
            running = false;
            break;
        }

        if (starts_with(line, "FROM ")) {
            std::string rest = line.substr(5);
            size_t space = rest.find(' ');
            if (space != std::string::npos) {
                std::string sender = rest.substr(0, space);
                std::string payload = rest.substr(space + 1);
                handle_incoming_message(sock, server_key, sender, payload);
            }
        } else if (starts_with(line, "USERS")) {
            std::cout << "\nOnline users: " << line.substr(5) << "\n> " << std::flush;
        } else if (starts_with(line, "ERR ")) {
            std::cout << "\n[ERROR] " << line.substr(4) << "\n> " << std::flush;
        } else if (starts_with(line, "OK ")) {
            std::cout << "\n[SERVER] " << line.substr(3) << "\n> " << std::flush;
        } else {
            std::cout << "\n[SERVER] " << line << "\n> " << std::flush;
        }
    }
}

void print_help() {
    std::cout << "\nCommands:\n"
              << "  @username message  Send message and select user\n"
              << "  /chat username     Select chat partner\n"
              << "  /e2e username      Initiate end-to-end encryption with user\n"
              << "  /who               Show online users\n"
              << "  /quit              Disconnect and exit\n"
              << "\nAny other text is sent to the selected user.\n\n";
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0]
                  << " <server_ip> <port> <username> <ca_cert_path> <expected_server_cn>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string username = argv[3];
    std::string ca_cert_path = argv[4];
    std::string expected_cn = argv[5];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP\n"; close(sock); return 1;
    }
    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect"); close(sock); return 1;
    }

    std::string pending;
    std::array<unsigned char, AES_KEY_SIZE> session_key;

    if (!client_perform_handshake(sock, pending, ca_cert_path, expected_cn, session_key)) {
        std::cerr << "[CLIENT] Aborting connection — server could not be authenticated.\n";
        close(sock);
        return 1;
    }

    send_secure_line(sock, session_key, "LOGIN " + username);

    std::atomic<bool> running(true);
    std::thread receiver(receive_messages, sock, std::move(pending), std::ref(session_key), std::ref(running));

    std::string selected_user;
    std::cout << "Connected as: " << username << std::endl;
    print_help();

    while (running) {
        std::cout << "> ";
        std::string input;
        if (!std::getline(std::cin, input)) break;
        if (input.empty()) continue;

        if (input == "/who") {
            send_secure_line(sock, session_key, "WHO");
        } else if (input == "/quit") {
            send_secure_line(sock, session_key, "QUIT");
            running = false;
            break;
        } else if (starts_with(input, "/chat ")) {
            std::string target = input.substr(6);
            if (target.empty()) { std::cout << "Usage: /chat username\n"; continue; }
            selected_user = target;
            std::cout << "Now chatting with: " << selected_user << std::endl;
        } else if (starts_with(input, "/e2e ")) {
            std::string target = input.substr(5);
            if (target.empty()) { std::cout << "Usage: /e2e username\n"; continue; }
            initiate_e2e(sock, session_key, target);
        } else if (input[0] == '@') {
            size_t space = input.find(' ');
            if (space == std::string::npos) { std::cout << "Usage: @username message\n"; continue; }
            std::string target = input.substr(1, space - 1);
            std::string message = input.substr(space + 1);
            if (target.empty() || message.empty()) { std::cout << "Usage: @username message\n"; continue; }
            selected_user = target;
            send_chat_message(sock, session_key, selected_user, message);
        } else {
            if (selected_user.empty()) {
                std::cout << "No chat partner selected.\nUse /chat username or @username message\n";
                continue;
            }
            send_chat_message(sock, session_key, selected_user, input);
        }
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    if (receiver.joinable()) receiver.join();
    return 0;
}
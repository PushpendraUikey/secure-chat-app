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
#include <chrono>

const std::string TAG_E2E_INIT       = "__E2E_INIT__";
const std::string TAG_E2E_ACK        = "__E2E_ACK__";
const std::string TAG_E2E_MSG        = "__E2E_MSG__";
const std::string TAG_E2E_REKEY_INIT = "__E2E_REKEY_INIT__";
const std::string TAG_E2E_REKEY_ACK  = "__E2E_REKEY_ACK__";

constexpr int REKEY_INTERVAL_SECONDS = 60;
// If a REKEY_INIT we sent never gets an ACK within this window (peer
// disconnected mid-handshake, message dropped, malformed response),
// we clear the stuck pending entry so rotation can be retried rather
// than being permanently stuck for that peer.
constexpr int REKEY_PENDING_TIMEOUT_SECONDS = 10;

struct E2ESession {
    std::array<unsigned char, AES_KEY_SIZE> current_key;
    std::array<unsigned char, AES_KEY_SIZE> previous_key;
    std::chrono::steady_clock::time_point last_rotation;
    bool has_previous = false;
};

struct PendingRekey {
    std::shared_ptr<DiffieHellman> dh;
    std::chrono::steady_clock::time_point started_at;
};

// E2E session state, guarded by e2e_mutex throughout.
std::map<std::string, E2ESession> e2e_sessions;
std::map<std::string, std::shared_ptr<DiffieHellman>> pending_dh;       // initial handshake
std::map<std::string, PendingRekey> pending_rekey_dh;                    // rekey handshake, now timestamped
std::mutex e2e_mutex;

std::mutex send_mutex;

bool send_secure_line(int sock, const std::array<unsigned char, AES_KEY_SIZE>& key, const std::string& message) {
    std::string blob = encrypt_message(key, message);
    std::string b64 = base64_encode(blob);
    std::lock_guard<std::mutex> lock(send_mutex);
    return send_line(sock, b64);
}

// Shared by both the automatic 60s timer AND the manual /rekey debug
// command, so there is exactly one code path that can ever send a
// REKEY_INIT — no risk of the two diverging in behavior.
//
// Returns false (does nothing) if there's no established session with
// `target`, or a rekey is already in flight — in the latter case, if
// that in-flight attempt is stale (older than REKEY_PENDING_TIMEOUT_SECONDS),
// it is cleared first so a fresh attempt can proceed instead of staying
// stuck forever.
bool trigger_rekey(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    const std::string& target
) {
    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        if (!e2e_sessions.count(target)) {
            return false; // nothing to rekey — no established session
        }

        auto it = pending_rekey_dh.find(target);
        if (it != pending_rekey_dh.end()) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - it->second.started_at).count();
            if (age < REKEY_PENDING_TIMEOUT_SECONDS) {
                return false; // genuinely still in flight, don't double-send
            }
            // Stale — the peer never answered. Clear it and retry.
            pending_rekey_dh.erase(it);
        }
    }

    auto dh = std::make_shared<DiffieHellman>();
    dh->generate_keypair();
    std::string pub_hex = dh->get_public_value_hex();

    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        // Re-check under lock: peer's own REKEY_INIT could have arrived
        // and been processed between the check above and now.
        if (pending_rekey_dh.count(target)) return false;
        pending_rekey_dh[target] = {dh, std::chrono::steady_clock::now()};
    }

    send_secure_line(sock, server_key, "MSG " + target + " " + TAG_E2E_REKEY_INIT + pub_hex);
    return true;
}

void e2e_timer_thread(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    std::atomic<bool>& running
) {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto now = std::chrono::steady_clock::now();
        std::string target_to_rekey;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            for (auto& pair : e2e_sessions) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - pair.second.last_rotation).count();
                if (elapsed >= REKEY_INTERVAL_SECONDS) {
                    target_to_rekey = pair.first;
                    break;
                }
            }
        }

        if (!target_to_rekey.empty()) {
            trigger_rekey(sock, server_key, target_to_rekey);
        }
    }
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
        auto it = e2e_sessions.find(target);
        if (it != e2e_sessions.end()) {
            peer_key = it->second.current_key;
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
                     "the outer client-server tunnel only.\n";
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
        if (e2e_sessions.count(target)) {
            std::cout << "[*] Already have an established E2E session with " << target << ".\n";
            return;
        }
        if (pending_dh.count(target)) {
            std::cout << "[*] E2E handshake with " << target << " is already in progress.\n";
            return;
        }
    }

    auto dh = std::make_shared<DiffieHellman>();
    dh->generate_keypair();
    std::string pub_hex = dh->get_public_value_hex();

    {
        std::lock_guard<std::mutex> lock(e2e_mutex);
        if (pending_dh.count(target) || e2e_sessions.count(target)) return;
        pending_dh[target] = dh;
    }

    send_secure_line(sock, server_key, "MSG " + target + " " + TAG_E2E_INIT + pub_hex);
    std::cout << "[*] Sent E2E key exchange request to " << target << "...\n";
}

void handle_incoming_message(
    int sock,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    const std::string& current_username,
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
                dh = it->second;
                reusing_existing = true;
            } else {
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
                e2e_sessions[sender] = {key, {}, std::chrono::steady_clock::now(), false};
                if (reusing_existing) pending_dh.erase(sender);
            }

            std::cout << "\n[*] End-to-End session established with " << sender << "\n";
            std::cout << "[*] E2E Key Fingerprint: " << fingerprint(shared_secret) << "\n> " << std::flush;
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
            } else if (e2e_sessions.count(sender)) {
                already_established = true;
            }
        }

        if (already_established || !dh) return;

        try {
            std::string shared_secret = dh->compute_shared_secret(peer_pub_hex);
            auto key = derive_key(shared_secret);

            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                e2e_sessions[sender] = {key, {}, std::chrono::steady_clock::now(), false};
            }

            std::cout << "\n[*] End-to-End session established with " << sender << "\n";
            std::cout << "[*] E2E Key Fingerprint: " << fingerprint(shared_secret) << "\n> " << std::flush;
        } catch (const std::exception& e) {
            std::cout << "\n[!] Failed to complete E2E ACK from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    // --- 3. Rekey initiation from peer ---
    else if (starts_with(payload, TAG_E2E_REKEY_INIT)) {
        std::string peer_pub_hex = payload.substr(TAG_E2E_REKEY_INIT.size());

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            // FIX: a rekey only makes sense as a continuation of an
            // ALREADY-ESTABLISHED session. Without this check,
            // e2e_sessions[sender] below would default-construct a
            // brand-new session out of nothing — meaning anyone could
            // fabricate a "live E2E session" with you just by sending
            // a bare REKEY_INIT, with no prior INIT/ACK ever occurring.
            if (!e2e_sessions.count(sender)) {
                std::cout << "\n[!] Ignored REKEY_INIT from " << sender
                          << " — no established E2E session exists with them.\n> " << std::flush;
                return;
            }

            auto it = pending_rekey_dh.find(sender);
            if (it != pending_rekey_dh.end()) {
                // Collision tie-breaker: lexicographically smaller
                // username's rekey attempt wins; the other side drops
                // its own attempt and answers instead.
                if (current_username < sender) return;
                pending_rekey_dh.erase(it);
            }
        }

        try {
            DiffieHellman dh;
            dh.generate_keypair();
            std::string shared_secret = dh.compute_shared_secret(peer_pub_hex);
            auto new_key = derive_key(shared_secret);

            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                auto it = e2e_sessions.find(sender);
                if (it == e2e_sessions.end()) return; // session torn down concurrently — abandon
                it->second.previous_key = it->second.current_key;
                it->second.has_previous = true;
                it->second.current_key = new_key;
                it->second.last_rotation = std::chrono::steady_clock::now();
            }

            std::cout << "\n[*] Session Key Rotated with " << sender << ". New Fingerprint: "
                      << fingerprint(shared_secret) << "\n> " << std::flush;
            send_secure_line(sock, server_key, "MSG " + sender + " " + TAG_E2E_REKEY_ACK + dh.get_public_value_hex());
        } catch (const std::exception& e) {
            std::cout << "\n[!] Failed to complete REKEY INIT from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    // --- 4. Rekey acknowledgment from peer ---
    else if (starts_with(payload, TAG_E2E_REKEY_ACK)) {
        std::string peer_pub_hex = payload.substr(TAG_E2E_REKEY_ACK.size());
        std::shared_ptr<DiffieHellman> dh;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = pending_rekey_dh.find(sender);
            if (it != pending_rekey_dh.end()) {
                dh = it->second.dh;
                pending_rekey_dh.erase(it);
            }
        }

        if (!dh) return; // unsolicited or already-timed-out ACK — ignore

        try {
            std::string shared_secret = dh->compute_shared_secret(peer_pub_hex);
            auto new_key = derive_key(shared_secret);

            {
                std::lock_guard<std::mutex> lock(e2e_mutex);
                auto it = e2e_sessions.find(sender);
                if (it == e2e_sessions.end()) return;
                it->second.previous_key = it->second.current_key;
                it->second.has_previous = true;
                it->second.current_key = new_key;
                it->second.last_rotation = std::chrono::steady_clock::now();
            }

            std::cout << "\n[*] Session Key Rotated with " << sender << ". New Fingerprint: "
                      << fingerprint(shared_secret) << "\n> " << std::flush;
        } catch (const std::exception& e) {
            std::cout << "\n[!] Failed to complete REKEY ACK from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    // --- 5. Inner-layer encrypted chat message ---
    else if (starts_with(payload, TAG_E2E_MSG)) {
        std::string inner_b64 = payload.substr(TAG_E2E_MSG.size());
        std::array<unsigned char, AES_KEY_SIZE> curr_key, prev_key;
        bool has_key = false, has_prev = false;

        {
            std::lock_guard<std::mutex> lock(e2e_mutex);
            auto it = e2e_sessions.find(sender);
            if (it != e2e_sessions.end()) {
                curr_key = it->second.current_key;
                prev_key = it->second.previous_key;
                has_prev = it->second.has_previous;
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
            std::string plaintext;
            try {
                plaintext = decrypt_message(curr_key, inner_blob);
            } catch (...) {
                if (has_prev) plaintext = decrypt_message(prev_key, inner_blob);
                else throw;
            }
            std::cout << "\n[" << sender << " (E2E)] " << plaintext << "\n> " << std::flush;
        } catch (const std::exception& e) {
            std::cout << "\n[CRYPTO ERROR] E2E Decryption/Tamper failure from " << sender << ": " << e.what() << "\n> " << std::flush;
        }
    }
    else {
        std::cout << "\n[" << sender << "] " << payload << "\n> " << std::flush;
    }
}

void receive_messages(
    int sock,
    std::string pending,
    const std::array<unsigned char, AES_KEY_SIZE>& server_key,
    const std::string& current_username,
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
                handle_incoming_message(sock, server_key, current_username, sender, payload);
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
              << "  /rekey username    Force an immediate E2E key rotation (testing)\n"
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
    std::thread receiver(receive_messages, sock, std::move(pending), std::ref(session_key), username, std::ref(running));
    std::thread timer(e2e_timer_thread, sock, std::ref(session_key), std::ref(running));

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
        } else if (starts_with(input, "/rekey ")) {
            std::string target = input.substr(7);
            if (target.empty()) { std::cout << "Usage: /rekey username\n"; continue; }
            if (!trigger_rekey(sock, session_key, target)) {
                std::cout << "[*] Could not rekey with " << target
                          << " — either no established E2E session exists, "
                             "or a rekey is already in progress.\n";
            } else {
                std::cout << "[*] Manual rekey requested with " << target << "...\n";
            }
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
    if (timer.joinable()) timer.join();
    return 0;
}
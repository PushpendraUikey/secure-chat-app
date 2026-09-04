CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
LDFLAGS = -lcrypto

all: server client mitm

server: server.cpp dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp protocol.h dh.h crypto_utils.h aes_gcm.h base64.h pki.h handshake.h net_io.h openssl_raii.h
	$(CXX) $(CXXFLAGS) server.cpp dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp -o server $(LDFLAGS)

client: client.cpp dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp protocol.h dh.h crypto_utils.h aes_gcm.h base64.h pki.h handshake.h net_io.h openssl_raii.h
	$(CXX) $(CXXFLAGS) client.cpp dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp -o client $(LDFLAGS)

mitm: mitm.cpp dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp protocol.h dh.h crypto_utils.h aes_gcm.h base64.h pki.h handshake.h net_io.h openssl_raii.h
	$(CXX) $(CXXFLAGS) mitm.cpp dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp -o mitm $(LDFLAGS)

clean:
	rm -f server client mitm
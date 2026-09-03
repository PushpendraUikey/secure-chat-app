CXX = c++

CXXFLAGS = -std=c++17 -Wall -Wextra -pthread

LDFLAGS = -lcrypto

UTILS = ./dh.cpp ./crypto_utils.cpp ./aes_gcm.cpp ./base64.cpp

all: server client

server: server.cpp protocol.h $(UTILS)
	$(CXX) $(CXXFLAGS) server.cpp $(UTILS) -o server $(LDFLAGS)

client: client.cpp protocol.h $(UTILS)
	$(CXX) $(CXXFLAGS) client.cpp $(UTILS) -o client $(LDFLAGS)

clean:
	rm -f server client
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS := -lcrypto -lpthread

COMMON_SRCS := dh.cpp crypto_utils.cpp aes_gcm.cpp base64.cpp pki.cpp handshake.cpp net_io.cpp
COMMON_OBJS := $(COMMON_SRCS:.cpp=.o)

.PHONY: all clean

all: server client proxy

server: server.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

client: client.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

proxy: proxy.cpp $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $

clean:
	rm -f server client proxy *.o
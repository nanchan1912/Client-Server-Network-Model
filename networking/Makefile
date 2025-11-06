# Simple Makefile for S.H.A.M. Protocol
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto

# Source files
CLIENT_SRC = client.c
SERVER_SRC = server.c
HEADER = networking.h

# Executables
CLIENT = client
SERVER = server

# Build client
client: $(CLIENT_SRC) $(HEADER)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $(CLIENT) $(LDFLAGS)
	@echo "Client built successfully!"

# Build server
server: $(SERVER_SRC) $(HEADER)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER) $(LDFLAGS)
	@echo "Server built successfully!"

# Clean build artifacts
clean:
	rm -f $(CLIENT) $(SERVER)
	@echo "Clean complete!"

.PHONY: client server clean

# Client-Server Network Model
> yo mama so fat, even her ACKs need flow control

This repo is a compact user-space implementation of multiple TCP features built on top of UDP. It has a small sliding-window file-transfer and chat system with simulated packet loss, retransmissions, a three-way handshake (SYN/SYN-ACK/ACK), and graceful teardown (FIN).

- `networking/client.c` — client implementation. Supports file transfer and interactive chat mode. Non-blocking sockets, sliding window sender, retransmissions, and optional logging.
- `networking/server.c` — server implementation. Accepts client connections, receives files or chat messages, writes received files and prints an MD5 checksum when finished.
- `networking/networking.h` — shared header with packet format, constants, and utility prototypes.

Build
-----

```powershell
# Builx server
gcc -o server server.c -lcrypto
# Build client
gcc -o client client.c
```

You can also run `make` or the target specified in the Makefile.

Run / Usage
-----------
Server:

```powershell
# File transfer mode (port 9000)
.\server 9000

# Chat mode (port 9000)
.\server 9000 --chat

# Optional: simulate packet loss by providing a loss rate between 0 and 1
.\server 9000 0.1   # 10% simulated packet loss
```

Client:

```powershell
# File transfer: client <server_ip> <server_port> <input_file> <dest_filename> [loss_rate]
.\client 127.0.0.1 9000 ./myfile.bin received_on_server.bin 0.05

# Chat mode:
.\client 127.0.0.1 9000 --chat
```

Notes:
- Set environment variable `RUDP_LOG=1` to enable verbose logging; logs are written to `client_log.txt` and `server_log.txt` when enabled.
- The `loss_rate` argument (optional) simulates packet drops on the server side and the client also accepts it. Use values like `0.0`, `0.05`, `0.1`.

Protocol and behavior summary
-----------------------------
- Three-way handshake: client sends SYN, server replies SYN+ACK, client replies final ACK.
- File transfer uses a sliding-window sender on the client side with cumulative ACKs sent by the server.
- Retransmission timeout: controlled by the constant `RETRANSMISSION_TIMEOUT_MS` in `networking.h` (default 500 ms).
- The server computes and prints an MD5 hash of the received file once transfer completes.




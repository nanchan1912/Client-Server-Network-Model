#ifndef NETWORKING_H
#define NETWORKING_H

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <stdarg.h>

// S.H.A.M. PACKET STRUCTURE
// Define the S.H.A.M. packet header structure
#pragma pack(push, 1)
struct sham_header {
    uint32_t seq_num;       // Sequence Number
    uint32_t ack_num;       // Acknowledgment Number
    uint16_t flags;         // Control flags (SYN, ACK, FIN)
    uint16_t window_size;   // Flow control window size
};
#pragma pack(pop)

// Define control flags
#define SYN 0x1
#define ACK 0x2
#define FIN 0x4

// Constants
#define PACKET_DATA_SIZE 1024
#define SHAM_HEADER_SIZE sizeof(struct sham_header)
#define BUFFER_SIZE (SHAM_HEADER_SIZE + PACKET_DATA_SIZE)
#define MAX_BUFFER_SIZE (60 * PACKET_DATA_SIZE)
#define RETRANSMISSION_TIMEOUT_MS 500
#define WINDOW_SIZE 10

struct Packet {
    char data[BUFFER_SIZE];
    int len;
    struct timeval sent_time;
    int retransmissions;
};
// --- VERBOSE LOGGING ---
// Function prototypes for logging and utility functions
extern FILE *log_file;
extern int logging_enabled;

void get_current_time(char *buffer);
void log_event(const char *format, ...);
void print_packet(const char* action, const char* role, const struct sham_header* header, int data_len);
long long time_diff_ms(struct timeval start, struct timeval end);

#endif // NETWORKING_H

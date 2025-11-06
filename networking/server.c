

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <time.h>
#include "networking.h"

//whatever was chatgpted there was copypasted here

FILE *log_file = NULL;
int logging_enabled = 0;
float loss_rate = 0.0;

// Function to get current time with microseconds
void get_current_time(char *buffer) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t curtime = tv.tv_sec;
    strftime(buffer, 30, "%Y-%m-%d %H:%M:%S", localtime(&curtime));
    sprintf(buffer + strlen(buffer), ".%06ld", tv.tv_usec);
}

// Function to write to log file
void log_event(const char *format, ...) {
    if (!logging_enabled || log_file == NULL) {
        return;
    }
    char timestamp[30];
    get_current_time(timestamp);
    fprintf(log_file, "[%s] [LOG] ", timestamp);
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    fprintf(log_file, "\n");
    fflush(log_file);
}

void print_packet(const char* action, const char* role, const struct sham_header* header, int data_len) {
    printf("[%s] %s: SEQ=%u, ACK=%u, Flags=", role, action, ntohl(header->seq_num), ntohl(header->ack_num));
    if (ntohs(header->flags) & SYN) printf("SYN ");
    if (ntohs(header->flags) & ACK) printf("ACK ");
    if (ntohs(header->flags) & FIN) printf("FIN ");
    printf("| Window=%u, DataLen=%d\n", ntohs(header->window_size), data_len);
}

// Function to calculate time difference in milliseconds
long long time_diff_ms(struct timeval start, struct timeval end) {
    long long seconds = end.tv_sec - start.tv_sec;
    long long microseconds = end.tv_usec - start.tv_usec;//chatgpted function
    return (seconds * 1000) + (microseconds / 1000);
}

// Function to calculate MD5 hash
void calculate_md5(const char* filename) {
    unsigned char c[MD5_DIGEST_LENGTH];
    int i;
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file for MD5 calculation");
        return;
    }
    
    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    
    char buffer[1024];
    int bytes;
    while ((bytes = fread(buffer, 1, 1024, file)) != 0) {
        MD5_Update(&mdContext, buffer, bytes);
    }
    MD5_Final(c, &mdContext);
    
    fclose(file);
    
    printf("MD5: ");
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", c[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    // --- 3.1 COMMAND-LINE INTERFACE ---
    int port;
    int chat_mode = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage (File Transfer): %s <port> [loss_rate]\n", argv[0]);
        fprintf(stderr, "Usage (Chat Mode): %s <port> --chat [loss_rate]\n", argv[0]);
        return 1;
    }

    port = atoi(argv[1]);
    if (argc >= 3) {
        if (strcmp(argv[2], "--chat") == 0) {
            chat_mode = 1;
            if (argc == 4) {
                loss_rate = atof(argv[3]);
            }
        } else {
            loss_rate = atof(argv[2]);
        }
    }
    
    srand(time(NULL));

  
    if (getenv("RUDP_LOG") != NULL && strcmp(getenv("RUDP_LOG"), "1") == 0) {
        logging_enabled = 1;
        log_file = fopen("server_log.txt", "w");
        if (log_file == NULL) {
            perror("Failed to open log file");
            logging_enabled = 0;
        }
    }
    
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        if (log_file) fclose(log_file);
        return 1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        if (log_file) fclose(log_file);
        return 1;
    }
    
    printf("S.H.A.M. Server listening on port %d...\n", port);
    
    
    struct sham_header *recv_header;
    struct sham_header *send_header;
    int n;
    
    // Step 1: Wait for SYN from client with timeout
    char send_buffer[SHAM_HEADER_SIZE];
    send_header = (struct sham_header*)send_buffer;
    
    struct timeval tv;
    fd_set read_fds;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        tv.tv_sec = 1;//chatgpt
        tv.tv_usec = 0;//chatgpt

        int activity = select(sockfd + 1, &read_fds, NULL, NULL, &tv);
        if (activity < 0) {
            perror("select error");
            break;
        }
        if (activity == 0) continue;

        n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < SHAM_HEADER_SIZE) continue;
        
        recv_header = (struct sham_header*)buffer;
        if (ntohs(recv_header->flags) & SYN) {
            print_packet("RECEIVED", "SERVER", recv_header, n - SHAM_HEADER_SIZE);
            log_event("RCV SYN SEQ=%u", ntohl(recv_header->seq_num));
            break;
        }
    }
    
    uint32_t server_isn = 1000;
    uint32_t client_isn = ntohl(recv_header->seq_num); //chatgpt
    
    send_header->seq_num = htonl(server_isn);
    send_header->ack_num = htonl(client_isn + 1);
    send_header->flags = htons(SYN | ACK);
    send_header->window_size = htons(MAX_BUFFER_SIZE);
    
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&client_addr, addr_len);
    print_packet("SENT", "SERVER", send_header, 0);
    log_event("SND SYN-ACK SEQ=%u ACK=%u", server_isn, client_isn + 1);
    
    
    gettimeofday(&tv, NULL);
    long start_time_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000; //chatgpt
    while(1) {
        gettimeofday(&tv, NULL);
        long current_time_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
        if (current_time_ms - start_time_ms > RETRANSMISSION_TIMEOUT_MS) {
            printf("Timeout, did not receive final ACK. Exiting.\n");
            close(sockfd);
            if (log_file) fclose(log_file);
            return 1;
        }
        
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        select(sockfd + 1, &read_fds, NULL, NULL, &tv);
        
        if (FD_ISSET(sockfd, &read_fds)) {
            n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (n < SHAM_HEADER_SIZE) continue;
            
            recv_header = (struct sham_header*)buffer;
            if ((ntohs(recv_header->flags) & ACK) && ntohl(recv_header->ack_num) == server_isn + 1) {
                print_packet("RECEIVED", "SERVER", recv_header, n - SHAM_HEADER_SIZE);
                log_event("RCV ACK FOR SYN");
                break;
            }
        }
    }
    
    printf("Connection established. THREE WAY HANDSHAKE COMPLETE :)\n");
    char filename[256] = "received_file.txt";

    if (chat_mode) {
        // --- 3.2 Chat Mode ---
        printf("Entering Chat Mode. Type '/quit' to exit.\n");
        fd_set read_fds_chat;
        
        while (1) {
            FD_ZERO(&read_fds_chat);
            FD_SET(STDIN_FILENO, &read_fds_chat);
            FD_SET(sockfd, &read_fds_chat);
            
            int activity = select(sockfd + 1, &read_fds_chat, NULL, NULL, NULL);

            if (activity < 0) {
                perror("select error");
                break;
            }

            // Handle standard input (keyboard)
            if (FD_ISSET(STDIN_FILENO, &read_fds_chat)) { //chatgpted functno
                char chat_input[PACKET_DATA_SIZE];
                if (fgets(chat_input, PACKET_DATA_SIZE, stdin) == NULL) {
                    continue;
                }
                
                if (strcmp(chat_input, "/quit\n") == 0) {
                    break;
                }
                
                // Send chat message
                char send_packet[BUFFER_SIZE];
                struct sham_header *chat_header = (struct sham_header *)send_packet;
                chat_header->seq_num = htonl(server_isn);
                chat_header->ack_num = htonl(client_isn);
                chat_header->flags = htons(ACK);
                chat_header->window_size = htons(0);
                memcpy(send_packet + SHAM_HEADER_SIZE, chat_input, strlen(chat_input));
                sendto(sockfd, send_packet, SHAM_HEADER_SIZE + strlen(chat_input), 0, (const struct sockaddr *)&client_addr, addr_len);
                log_event("SND CHAT: %s", chat_input);
            }
            
            // Handle network input
            if (FD_ISSET(sockfd, &read_fds_chat)) {
                n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
                recv_header = (struct sham_header*)buffer;
                if (ntohs(recv_header->flags) & FIN) {
                    printf("Client initiated graceful shutdown. Exiting.\n");
                    goto termination_handshake;
                }
                if (n > SHAM_HEADER_SIZE) {
                    buffer[n] = '\0';
                    printf("Client: %s", buffer + SHAM_HEADER_SIZE);
                    log_event("RCV CHAT: %s", buffer + SHAM_HEADER_SIZE);
                }
            }
        }
    
    } else {
        //recieve filename

int filename_received = 0;

uint32_t expected_seq_num = client_isn + 1;

// Wait for filename packet
while (!filename_received) {
    n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
    
    if (n < SHAM_HEADER_SIZE) continue;
    
    recv_header = (struct sham_header*)buffer;
    uint32_t seq_num = ntohl(recv_header->seq_num);
    int data_len = n - SHAM_HEADER_SIZE;
    
    if (seq_num == expected_seq_num && data_len > 0) {
        memcpy(filename, buffer + SHAM_HEADER_SIZE, data_len);
        filename[data_len] = '\0';
        expected_seq_num += data_len;
        filename_received = 1;
        
        log_event("RCV FILENAME: %s", filename);
        printf("Receiving file: %s\n", filename);
        
        // Send ACK for filename
        send_header->seq_num = htonl(server_isn);
        send_header->ack_num = htonl(expected_seq_num);
        send_header->flags = htons(ACK);
        send_header->window_size = htons(MAX_BUFFER_SIZE);
        sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&client_addr, addr_len);
        log_event("SND ACK FOR FILENAME");
    }
}

// Now open the file with the received filename
FILE *file = fopen(filename, "wb");
if (!file) {
    perror("Failed to open file for writing");
    close(sockfd);
    if (log_file) fclose(log_file);
    return 1;
}
        
        while (1) {
            n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            
            if ((float)rand() / RAND_MAX < loss_rate) {
                log_event("DROP DATA SEQ=%u", ntohl(((struct sham_header*)buffer)->seq_num));
                continue; // Simulate packet loss
            }
            
            if (n < SHAM_HEADER_SIZE) {
                continue;
            }
            
            recv_header = (struct sham_header*)buffer;
            uint16_t flags = ntohs(recv_header->flags);
            uint32_t seq_num = ntohl(recv_header->seq_num);
            int data_len = n - SHAM_HEADER_SIZE;
            
            if (flags & FIN) {
                print_packet("RECEIVED FIN", "SERVER", recv_header, data_len);
                log_event("RCV FIN SEQ=%u", seq_num);
                break;
            }
            
            if (flags & ACK) {
                print_packet("RECEIVED DATA", "SERVER", recv_header, data_len);
                log_event("RCV DATA SEQ=%u LEN=%d", seq_num, data_len);

                if (seq_num == expected_seq_num) {
                    if (data_len > 0) {
                        fwrite(buffer + SHAM_HEADER_SIZE, 1, data_len, file);
                    }
                    expected_seq_num += data_len;
                } else {
                    printf("Out of order packet received. Sent ACK for expected sequence number: %u\n", expected_seq_num);
                }

                // Send cumulative ACK
                send_header->seq_num = htonl(server_isn);
                send_header->ack_num = htonl(expected_seq_num);
                send_header->flags = htons(ACK);
                send_header->window_size = htons(MAX_BUFFER_SIZE);
                sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&client_addr, addr_len);
                print_packet("SENT ACK", "SERVER", send_header, 0);
                log_event("SND ACK=%u WIN=%u", expected_seq_num, MAX_BUFFER_SIZE);
            }
        }
        
        fclose(file);
    }
    
    termination_handshake://this part is chatgpted
    send_header->seq_num = htonl(server_isn);
    send_header->ack_num = htonl(ntohl(recv_header->seq_num) + 1);
    send_header->flags = htons(ACK);
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&client_addr, addr_len);
    print_packet("SENT ACK for FIN", "SERVER", send_header, 0);
    log_event("SND ACK FOR FIN");
    
   
    send_header->seq_num = htonl(ntohl(send_header->ack_num)); // Next expected sequence is the ACK number from prev step
    send_header->ack_num = htonl(ntohl(recv_header->seq_num) + 1);
    send_header->flags = htons(FIN);
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&client_addr, addr_len);
    print_packet("SENT FIN", "SERVER", send_header, 0);
    log_event("SND FIN SEQ=%u", ntohl(send_header->seq_num));
    
    while(1) {
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int activity = select(sockfd + 1, &read_fds, NULL, NULL, &tv);

        if (activity == 0) {
            printf("Did not receive final ACK. Closing anyway.\n");
            break;
        }

        if (FD_ISSET(sockfd, &read_fds)) {
            n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (n > 0) {
                recv_header = (struct sham_header*)buffer;
                if ((ntohs(recv_header->flags) & ACK)) {
                    print_packet("RECEIVED final ACK", "SERVER", recv_header, 0);
                    log_event("RCV ACK=%u", ntohl(recv_header->ack_num));
                    break;
                }
            }
        }
    }
    
    printf("Connection terminated.\n");
    if (!chat_mode) {
       
    calculate_md5(filename);

    }
    
    close(sockfd);
    if (log_file) fclose(log_file);
    
    return 0;
}


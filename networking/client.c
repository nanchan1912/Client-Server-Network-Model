
// sham_client.c
//
// This program implements the client-side of the S.H.A.M. protocol, a simplified
// reliable transport protocol built on top of UDP. It handles connection
// establishment, file transfer using a sliding window, retransmissions, and
// connection termination.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include "networking.h"

// Globals for logging
FILE *log_file = NULL;
int logging_enabled = 0;
float loss_rate = 0.0;

// Function to get current time with microseconds //chatgpt
void get_current_time(char *buffer) {//chatgpt
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
    va_list args;//chatgpt
    va_start(args, format);//chatgpt
    vfprintf(log_file, format, args);
    va_end(args);
    fprintf(log_file, "\n");
    fflush(log_file);
}


// Function to print packet details to stdout
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
    long long microseconds = end.tv_usec - start.tv_usec;
    return (seconds * 1000) + (microseconds / 1000);
}

int main(int argc, char *argv[]) {
    
    char *server_ip, *input_file_name = NULL, *output_file_name = NULL;
    int server_port;
    int chat_mode = 0;

    if (argc < 4) {
        fprintf(stderr, "Usage (File Transfer): %s <server_ip> <server_port> <input_file> <output_file> [loss_rate]\n", argv[0]);
        fprintf(stderr, "Usage (Chat Mode): %s <server_ip> <server_port> --chat [loss_rate]\n", argv[0]);
        return 1;
    }

    server_ip = argv[1];
    server_port = atoi(argv[2]);

    if (strcmp(argv[3], "--chat") == 0) {
        chat_mode = 1;
        if (argc == 5) {
            loss_rate = atof(argv[4]);
        }
    } else {
        input_file_name = argv[3];
        output_file_name = argv[4];
        if (argc == 6) {
            loss_rate = atof(argv[5]);
        }
    }
   

    srand(time(NULL));

    
    if (getenv("RUDP_LOG") != NULL && strcmp(getenv("RUDP_LOG"), "1") == 0) {
        logging_enabled = 1;
        log_file = fopen("client_log.txt", "w");
        if (log_file == NULL) {
            perror("Failed to open log file");
            logging_enabled = 0;
        }
    }
    

    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        if (log_file) fclose(log_file);
        return 1;
    }
    
    // Set socket to non-blocking //chatgpt
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);//chatgpt
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        close(sockfd);
        if (log_file) fclose(log_file);
        return 1;
    }
    
    printf("Connecting to %s:%d...\n", server_ip, server_port);
    
    struct sham_header *recv_header, *send_header;
    char recv_buffer[BUFFER_SIZE];
    
    char send_buffer[SHAM_HEADER_SIZE];
    send_header = (struct sham_header*)send_buffer;
    
    uint32_t client_isn = 5000;
    uint32_t server_isn;
    uint32_t next_seq_num = client_isn + 1;

    // Client -> Server: SYN
    send_header->seq_num = htonl(client_isn);
    send_header->ack_num = htonl(0);
    send_header->flags = htons(SYN);
    send_header->window_size = htons(MAX_BUFFER_SIZE);
    
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&server_addr, addr_len);
    print_packet("SENT", "CLIENT", send_header, 0);
    log_event("SND SYN SEQ=%u", client_isn);

    // Syn ack
    int n;
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    long long elapsed_time;

    while (1) {
        gettimeofday(&current_time, NULL);
        elapsed_time = time_diff_ms(start_time, current_time);

        n = recvfrom(sockfd, (char *)recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &addr_len);
        if (n > 0) {
            recv_header = (struct sham_header*)recv_buffer;
            if ((ntohs(recv_header->flags) & SYN) && (ntohs(recv_header->flags) & ACK) && ntohl(recv_header->ack_num) == client_isn + 1) {
                print_packet("RECEIVED", "CLIENT", recv_header, 0);
                log_event("RCV SYN-ACK SEQ=%u ACK=%u", ntohl(recv_header->seq_num), ntohl(recv_header->ack_num));
                server_isn = ntohl(recv_header->seq_num);
                break;
            }
        } else if (elapsed_time > RETRANSMISSION_TIMEOUT_MS) {
            printf("Timeout, retransmitting SYN...\n");
            sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&server_addr, addr_len);
            gettimeofday(&start_time, NULL);
        }
    }
    
    // final ack
    send_header->seq_num = htonl(client_isn + 1);
    send_header->ack_num = htonl(server_isn + 1);
    send_header->flags = htons(ACK);
    send_header->window_size = htons(MAX_BUFFER_SIZE);
    
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&server_addr, addr_len);
    print_packet("SENT", "CLIENT", send_header, 0);
    log_event("SND ACK FOR SYN");

    printf("Connection established. Three way handshake done :)\n");
   
    if (chat_mode) {
       
        printf("Entering Chat Mode. Type '/quit' to exit.\n");
        fd_set read_fds;
        
        while (1) {//chatgpt
            FD_ZERO(&read_fds);
            FD_SET(STDIN_FILENO, &read_fds);
            FD_SET(sockfd, &read_fds);
            
            int max_fd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;
            int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

            if (activity < 0) {
                perror("select error");
                break;
            }//chatgpt end

            // Handle standard input (keyboard)
            if (FD_ISSET(STDIN_FILENO, &read_fds)) { //chatgpt
                char chat_input[PACKET_DATA_SIZE];
                if (fgets(chat_input, PACKET_DATA_SIZE, stdin) == NULL) {
                    continue;
                }
                
                if (strcmp(chat_input, "/quit\n") == 0) {
                    break;
                }
                //chatgpt end

                // Send chat message
                char send_packet[BUFFER_SIZE];
                struct sham_header *chat_header = (struct sham_header *)send_packet;
                chat_header->seq_num = htonl(client_isn);
                chat_header->ack_num = htonl(server_isn);
                chat_header->flags = htons(ACK);
                chat_header->window_size = htons(0);
                memcpy(send_packet + SHAM_HEADER_SIZE, chat_input, strlen(chat_input));
                sendto(sockfd, send_packet, SHAM_HEADER_SIZE + strlen(chat_input), 0, (const struct sockaddr *)&server_addr, addr_len);
                log_event("SND CHAT: %s", chat_input);
            }

            // Handle network input
            if (FD_ISSET(sockfd, &read_fds)) {//chatgpt condition
                n = recvfrom(sockfd, (char *)recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &addr_len);
                recv_header = (struct sham_header*)recv_buffer;
                if (ntohs(recv_header->flags) & FIN) {
                    printf("Server initiated graceful shutdown. Exiting.\n");
                    goto termination_handshake;
                }
                if (n > SHAM_HEADER_SIZE) {
                    recv_buffer[n] = '\0';
                    printf("Server: %s", recv_buffer + SHAM_HEADER_SIZE);
                    log_event("RCV CHAT: %s", recv_buffer + SHAM_HEADER_SIZE);
                }
            }
        }
    
    } else {
        
        FILE *file = fopen(input_file_name, "rb");
        if (!file) {
            perror("Failed to open input file");
            close(sockfd);
            if (log_file) fclose(log_file);
            return 1;
        }
        struct Packet packets[WINDOW_SIZE];
        uint32_t last_byte_acked = client_isn;
        uint32_t last_byte_sent = client_isn;

        char filename_packet[BUFFER_SIZE];
        struct sham_header *filename_header = (struct sham_header*)filename_packet;
        filename_header->seq_num = htonl(next_seq_num);
        filename_header->ack_num = htonl(0);
        filename_header->flags = htons(ACK);
        filename_header->window_size = htons(0);

// Use output_file_name (the desired filename on server)
int filename_len = strlen(output_file_name);
memcpy(filename_packet + SHAM_HEADER_SIZE, output_file_name, filename_len);

sendto(sockfd, filename_packet, SHAM_HEADER_SIZE + filename_len, 0, (const struct sockaddr *)&server_addr, addr_len);
print_packet("SENT FILENAME", "CLIENT", filename_header, filename_len);
log_event("SND FILENAME: %s", output_file_name);

next_seq_num += filename_len;
last_byte_sent = next_seq_num - 1;

       
        
        while (1) {
           
            if (last_byte_sent - last_byte_acked < WINDOW_SIZE * PACKET_DATA_SIZE) {
                char packet_data[PACKET_DATA_SIZE];
                int bytes_read = fread(packet_data, 1, PACKET_DATA_SIZE, file);
                
                if (bytes_read > 0) {
                    // Find an empty spot in the window
                    int index = (last_byte_sent / PACKET_DATA_SIZE) % WINDOW_SIZE;
                    
                    // Fill header
                    struct sham_header *header = (struct sham_header*)packets[index].data;
                    header->seq_num = htonl(last_byte_sent + 1);
                    header->ack_num = htonl(0); 
                    header->flags = htons(ACK);
                    header->window_size = htons(0);
                    packets[index].len = SHAM_HEADER_SIZE + bytes_read;
                    
                    memcpy(packets[index].data + SHAM_HEADER_SIZE, packet_data, bytes_read);
                    gettimeofday(&packets[index].sent_time, NULL);
                    
                    sendto(sockfd, packets[index].data, packets[index].len, 0, (const struct sockaddr *)&server_addr, addr_len);
                    print_packet("SENT DATA", "CLIENT", header, bytes_read);
                    log_event("SND DATA SEQ=%u LEN=%d", ntohl(header->seq_num), bytes_read);

                    last_byte_sent += bytes_read;
                } else if (last_byte_sent == last_byte_acked) {
                    // End of file and all bytes acknowledged
                    break;
                }
            }

            // Check for timeouts and incoming ACKs using select //chatgpt
            fd_set read_fds;
            struct timeval tv;
            int timeout_ms = RETRANSMISSION_TIMEOUT_MS;

            // Find the oldest packet's timeout
            if (last_byte_sent > last_byte_acked) {
                int oldest_packet_index = (last_byte_acked / PACKET_DATA_SIZE) % WINDOW_SIZE;
                long long time_since_sent = time_diff_ms(packets[oldest_packet_index].sent_time, current_time);
                if (time_since_sent < RETRANSMISSION_TIMEOUT_MS) {
                    timeout_ms = RETRANSMISSION_TIMEOUT_MS - time_since_sent;
                } else {
                    timeout_ms = 0; // Immediate timeout
                }
            }

            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);

            int activity = select(sockfd + 1, &read_fds, NULL, NULL, &tv);

            if (activity < 0) {
                if (errno != EINTR) {
                    perror("select error");
                    break;
                }
            }

            // Handle incoming ACKs or server FIN
            if (activity > 0 && FD_ISSET(sockfd, &read_fds)) {
                n = recvfrom(sockfd, (char *)recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &addr_len);
                if (n > 0) {
                    recv_header = (struct sham_header*)recv_buffer;
                    uint16_t flags = ntohs(recv_header->flags);
                    
                    if (flags & ACK) {
                        uint32_t ack_num = ntohl(recv_header->ack_num);
                        log_event("RCV ACK=%u", ack_num);
                        
                        if (ack_num > last_byte_acked) {
                            last_byte_acked = ack_num - 1;
                        }
                    } else if (flags & FIN) {
                        goto termination_handshake;
                    }
                }
            }
//chatgpted
            // Check for timeouts after select returns
            if (last_byte_sent > last_byte_acked) {
                gettimeofday(&current_time, NULL);
                int oldest_packet_index = (last_byte_acked / PACKET_DATA_SIZE) % WINDOW_SIZE;
                
                if (time_diff_ms(packets[oldest_packet_index].sent_time, current_time) >= RETRANSMISSION_TIMEOUT_MS) {
                    log_event("TIMEOUT SEQ=%u", ntohl(((struct sham_header*)packets[oldest_packet_index].data)->seq_num));
                    sendto(sockfd, packets[oldest_packet_index].data, packets[oldest_packet_index].len, 0, (const struct sockaddr *)&server_addr, addr_len);
                    log_event("RETX DATA SEQ=%u LEN=%d", ntohl(((struct sham_header*)packets[oldest_packet_index].data)->seq_num), packets[oldest_packet_index].len - SHAM_HEADER_SIZE);
                    gettimeofday(&packets[oldest_packet_index].sent_time, NULL); // Reset timer
                }
            }
        }//slightly chatgpted -> debugged
        
        fclose(file);
    }
   
    
   //4 way
   //chatgpted : didnt know how to fit all of them in one return, this function return and goto is chatgpt
    termination_handshake:
    // Step 1: Client -> Server: FIN
    send_header->seq_num = htonl(next_seq_num);
    send_header->ack_num = htonl(server_isn + 1);
    send_header->flags = htons(FIN);
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&server_addr, addr_len);
    print_packet("SENT FIN", "CLIENT", send_header, 0);
    log_event("SND FIN SEQ=%u", next_seq_num);
    
    // Use select to wait for packets with a timeout
    fd_set read_fds;
    struct timeval tv;
    int received_ack = 0;
    int received_fin = 0;

    // Loop until both ACK and FIN are received
    gettimeofday(&start_time, NULL);
    while (!received_ack || !received_fin) {//little chatgpted
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        
        gettimeofday(&current_time, NULL);
        long long elapsed_time_ms = time_diff_ms(start_time, current_time);
        long long timeout_remaining_us = (RETRANSMISSION_TIMEOUT_MS - elapsed_time_ms) * 1000;

        if (timeout_remaining_us < 0) {
            printf("Timeout, did not receive both ACK and FIN. Closing anyway.\n");
            break;
        }

        tv.tv_sec = timeout_remaining_us / 1000000;//chatgpt
        tv.tv_usec = timeout_remaining_us % 1000000;//chatgpt

        int activity = select(sockfd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0) {
            perror("select error");
            break;
        }

        if (activity == 0) { // Timeout
            printf("Timeout, did not receive both ACK and FIN. Closing anyway.\n");
            break;
        }

        if (FD_ISSET(sockfd, &read_fds)) {//chatgpt
            n = recvfrom(sockfd, (char *)recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &addr_len);
            if (n > 0) {
                recv_header = (struct sham_header*)recv_buffer;
                uint16_t flags = ntohs(recv_header->flags);
                
                if (flags & ACK) {
                    print_packet("RECEIVED ACK for FIN", "CLIENT", recv_header, 0);
                    log_event("RCV ACK=%u", ntohl(recv_header->ack_num));
                    received_ack = 1;
                }
                if (flags & FIN) {
                    print_packet("RECEIVED server's FIN", "CLIENT", recv_header, 0);
                    log_event("RCV FIN SEQ=%u", ntohl(recv_header->seq_num));
                    received_fin = 1;
                }
            }
        }
    }
    
    // Step 4: Send final ACK for the server's FIN
    send_header->seq_num = htonl(next_seq_num + 1);
    send_header->ack_num = htonl(ntohl(recv_header->seq_num) + 1);
    send_header->flags = htons(ACK);
    sendto(sockfd, (const char *)send_buffer, SHAM_HEADER_SIZE, 0, (const struct sockaddr *)&server_addr, addr_len);
    print_packet("SENT final ACK", "CLIENT", send_header, 0);
    log_event("SND ACK=%u", ntohl(send_header->ack_num));
    
    printf("Connection terminated.\n");
    

    close(sockfd);
    if (log_file) fclose(log_file);
    
    return 0;
}

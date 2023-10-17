#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024
#define DEST_IP "127.0.0.1"

void die_with_error(const char *error_msg) {
    perror(error_msg);
    exit(1);
}

#undef AF_PACKET
#define AF_PACKET 46 // AF_ENC

int main() {
    int sockfd;
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
        die_with_error("Unable to create socket");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(DEST_IP);

    // Send a test message to the server
    strcpy(buffer, "Hello, server!");
    ssize_t send_len = sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
    if (send_len < 0)
        die_with_error("Error sending message");

    printf("Sent %zd bytes to the server\n", send_len);

    struct sockaddr_in server_resp_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &server_resp_addr, &addr_len);
    if (recv_len < 0)
        die_with_error("Error receiving response");

    printf("Received %zd bytes from the server\n", recv_len);
    printf("Response: %s\n", buffer);

    close(sockfd);
    return 0;
}

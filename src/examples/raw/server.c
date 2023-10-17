#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

#define BUFFER_SIZE 1024

#undef AF_PACKET
#define AF_PACKET 46 // AF_ENC

void die_with_error(const char *error_msg) {
    perror(error_msg);
    exit(1);
}

int main() {
    int sockfd;
    char buffer[BUFFER_SIZE];

    sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
        die_with_error("Unable to create socket");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(struct sockaddr_in);
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &addr_len);
        if (recv_len < 0)
            die_with_error("Error receiving packet");

        printf("Received %zd bytes from %s\n", recv_len, inet_ntoa(client_addr.sin_addr));

        ssize_t send_len = sendto(sockfd, buffer, recv_len, 0, (struct sockaddr *) &client_addr, addr_len);
        if (send_len < 0)
            die_with_error("Error sending response");
    }

    close(sockfd);
    return 0;
}


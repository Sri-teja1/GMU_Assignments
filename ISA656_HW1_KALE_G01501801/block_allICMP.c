#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#define DIVERT_PORT 12345  // Divert socket port

int main() {
    int sock, n;
    struct sockaddr_in addr;
    unsigned char buf[65535];

    // Create divert socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(DIVERT_PORT);

    // Bind the socket
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    printf("Blocking all ICMP packets...\n");

    while (1) {
        struct sockaddr_in pkt_addr;
        socklen_t addr_len = sizeof(pkt_addr);

        // Receive packets
        n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&pkt_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        struct ip *ip_hdr = (struct ip *)buf;

        // Check if the protocol is ICMP (protocol number 1)
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            printf("Blocked ICMP packet from %s\n", inet_ntoa(ip_hdr->ip_src));
            continue;  // Do not reinject, effectively dropping the packet
        }

        // Reinject non-ICMP packets
        sendto(sock, buf, n, 0, (struct sockaddr *)&pkt_addr, addr_len);
    }

    close(sock);
    return 0;
}

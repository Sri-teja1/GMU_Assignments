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
#include <time.h>

#define DIVERT_PORT 12346

int main() {
    int sock, n;
    struct sockaddr_in addr;
    unsigned char buf[65535];

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(DIVERT_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    printf("Blocking all incoming packets except ICMP Echo Replies...\n");

    while (1) {
        struct sockaddr_in pkt_addr;
        socklen_t addr_len = sizeof(pkt_addr);

        n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&pkt_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        struct ip *ip_hdr = (struct ip *)buf;
        unsigned char *icmp_payload = buf + (ip_hdr->ip_hl * 4);

        if (ip_hdr->ip_p == IPPROTO_ICMP && icmp_payload[0] != 0) {
            printf("Blocked ICMP packet from %s\n", inet_ntoa(ip_hdr->ip_src));
            continue;
        }

        sendto(sock, buf, n, 0, (struct sockaddr *)&pkt_addr, addr_len);
    }

    close(sock);
    return 0;
}

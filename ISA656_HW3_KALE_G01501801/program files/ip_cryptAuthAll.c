#include "divertlib.h"
#include "md5.h"
#include <openssl/rc4.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define DEBUG
#define MAX_BUFLEN 1520
#define MD5_DIGEST_LENGTH 16

// External function declarations for ip_checksum.c
extern void ip_checksum(struct ip *ip);

// Function prototypes
void encrypt_payload(unsigned char *payload, int payload_len, const char *key);
void decrypt_payload(unsigned char *payload, int payload_len, const char *key);
int verify_authentication(unsigned char *payload, int payload_len, const char *key);

int main(int argc, char *argv[])
{
    int i, len, divsock;
    u_short iphlen;
    int DivPort;
    struct sockaddr_in sin;
    struct ip *iph;
    unsigned char buf[MAX_BUFLEN+1];
    unsigned char new_buf[MAX_BUFLEN+1];
    struct in_addr target_ip;
    char *key;
    int addrsize = sizeof(struct sockaddr);

    // Check command line arguments
    if (argc != 4) {
        puts("usage: ip_cryptAuthAll [divert port] [target IP] [secret key]");
        return 1;
    }

    // Parse arguments
    DivPort = atoi(argv[1]);
    target_ip.s_addr = inet_addr(argv[2]);
    key = argv[3];

    printf("DivPort=%d, Target IP=%s, Secret Key=%s\n", DivPort, argv[2], key);

    // Initialize divert socket
    if ((divsock = initDivSock(DivPort)) <= 0) {
        printf("Cannot get divert socket for port %d, divsock=%d\n", DivPort, divsock);
        exit(1);
    }

    for (i = 1; ; i++) {
        // Receive packet
        if ((len = recvfrom(divsock, buf, MAX_BUFLEN, 0, (struct sockaddr *)&sin, &addrsize)) > 0) {
            iph = (struct ip *)buf;
            iphlen = iph->ip_hl << 2;
            int payload_len = ntohs(iph->ip_len) - iphlen;
            unsigned char *payload = buf + iphlen;

		printf("hello");
            // Debug information
            #ifdef DEBUG
            if (sin.sin_addr.s_addr == INADDR_ANY) { /* outgoing */
                printf("\n%d : Out\t\t\t\t\t\t\t\t==>\n", i);
            } else { /* incoming */
                printf("\n%d : In from %s:%d\t\t\t\t\t\t<==\n", i, inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
            }
            printf("\tsrc IP:%s\n", inet_ntoa(iph->ip_src));
            printf("\tdst IP:%s\n", inet_ntoa(iph->ip_dst));
            printf("\tproto :%d\n", iph->ip_p);
            printf("\tpayload len: %d\n", payload_len);
            #endif
            // Process outgoing packets to target IP
            if (sin.sin_addr.s_addr == INADDR_ANY && iph->ip_dst.s_addr == target_ip.s_addr && payload_len > 0) {
                printf("Processing outgoing packet to target IP\n");
                
                // Copy the original packet to the new buffer
                memcpy(new_buf, buf, len);
                struct ip *new_iph = (struct ip *)new_buf;
                unsigned char *new_payload = new_buf + iphlen;
                
                // 1. Encrypt the payload with RC4
                encrypt_payload(new_payload, payload_len, key);
                
                // 2. Append MD5 authentication to the end
                md5_state_t md5_state;
                md5_byte_t digest[MD5_DIGEST_LENGTH];
                
                // Calculate MD5 of (encrypted payload + key)
                md5_init(&md5_state);
                md5_append(&md5_state, new_payload, payload_len);
                md5_append(&md5_state, (md5_byte_t *)key, strlen(key));
                md5_finish(&md5_state, digest);
                
                // Append MD5 to the payload
                memcpy(new_payload + payload_len, digest, MD5_DIGEST_LENGTH);
                
                // 3. Update IP header
                new_iph->ip_len = htons(ntohs(iph->ip_len) + MD5_DIGEST_LENGTH);
                ip_checksum(new_iph);  // Use the external ip_checksum function
                
                // Send modified packet
                if (sendto(divsock, new_buf, len + MD5_DIGEST_LENGTH, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
                    perror("Failed to send outgoing packet");
                }
                
                printf("Outgoing packet processed: payload encrypted and authenticated\n");
            }
            // Process incoming packets from target IP
            else if (sin.sin_addr.s_addr != INADDR_ANY && iph->ip_src.s_addr == target_ip.s_addr && payload_len > MD5_DIGEST_LENGTH) {
                printf("Processing incoming packet from target IP\n");
                
                // Verify authentication
                if (verify_authentication(payload, payload_len, key)) {
                    printf("Authentication successful\n");
                    
                    // Copy the original packet to the new buffer
                    memcpy(new_buf, buf, len);
                    struct ip *new_iph = (struct ip *)new_buf;
                    unsigned char *new_payload = new_buf + iphlen;
                    
                    // Split payload: encrypted part and MD5 part
                    int encrypted_len = payload_len - MD5_DIGEST_LENGTH;
                    
                    // Decrypt the payload
                    decrypt_payload(new_payload, encrypted_len, key);
                    
                    // Update IP header (reduce length by removing MD5)
                    new_iph->ip_len = htons(ntohs(iph->ip_len) - MD5_DIGEST_LENGTH);
                    ip_checksum(new_iph);  // Use the external ip_checksum function
                    
                    // Send modified packet (without the MD5 part)
                    if (sendto(divsock, new_buf, len - MD5_DIGEST_LENGTH, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
                        perror("Failed to send incoming packet");
                    }
                    
                    printf("Incoming packet processed: payload decrypted\n");
                } else {
                    printf("Authentication failed! Dropping packet.\n");
                    // Drop packet by not forwarding it
                }
            } else {
                // Forward unmodified packet
                if (sendto(divsock, buf, len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
                    perror("Failed to forward packet");
                }
            }
        }
    }
    
    return 0;
}

// Function to encrypt payload using RC4
void encrypt_payload(unsigned char *payload, int payload_len, const char *key) {
    RC4_KEY rc4_key;
    
    // Initialize RC4 key
    RC4_set_key(&rc4_key, strlen(key), (const unsigned char *)key);
    
    // Encrypt the payload in-place
    RC4(&rc4_key, payload_len, payload, payload);
}

// Function to decrypt payload using RC4
void decrypt_payload(unsigned char *payload, int payload_len, const char *key) {
    // RC4 decryption is the same as encryption
    encrypt_payload(payload, payload_len, key);
}

// Function to verify the MD5 authentication
int verify_authentication(unsigned char *payload, int payload_len, const char *key) {
    int encrypted_len = payload_len - MD5_DIGEST_LENGTH;
    unsigned char *received_digest = payload + encrypted_len;
    unsigned char calculated_digest[MD5_DIGEST_LENGTH];
    md5_state_t md5_state;
    
    // Calculate MD5 of (encrypted payload + key)
    md5_init(&md5_state);
    md5_append(&md5_state, payload, encrypted_len);
    md5_append(&md5_state, (md5_byte_t *)key, strlen(key));
    md5_finish(&md5_state, calculated_digest);
    
    // Compare with received digest
    return (memcmp(calculated_digest, received_digest, MD5_DIGEST_LENGTH) == 0);
}
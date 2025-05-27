
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>    // For u_char, u_short
#include <netinet/in.h>   // For struct in_addr, ntohs, htons
#include <arpa/inet.h>    // For inet_addr, inet_ntoa, etc.

#include <netinet/ip.h>   // For struct ip
#include <netinet/ip_var.h> // If needed

int SumWords(uint16_t *buf, int nwords)
{
  register uint32_t sum = 0;

  while (nwords >= 16)
  {
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    sum += (uint16_t) ntohs(*buf++);
    nwords -= 16;
  }
  while (nwords--)
    sum += (uint16_t) ntohs(*buf++);
  return(sum);
}

/*
 * ip_checksum()
 *
 * Recompute an IP header checksum
 */
void ip_checksum(struct ip *ip)
{
  register uint32_t sum;

  /* Sum up IP header words */
  ip->ip_sum = 0;
  sum = SumWords((uint16_t *) ip, ip->ip_hl << 1);

  /* Flip it & stick it */
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;

  ip->ip_sum = htons(sum);
}

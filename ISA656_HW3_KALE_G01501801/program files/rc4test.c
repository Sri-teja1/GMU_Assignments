/*
  rc4test.c

*/

#include <openssl/rc4.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// key: 0xdeadbeef12345678	8 raw bytes in hex representation 
unsigned char key[]="\xde\xad\xbe\xef\x12\x34\x56\x78"; 
unsigned char plaintext[1024];
unsigned char plaintext2[1024];
unsigned char ciphertext[1024];

void printHexString(unsigned char *rawbytes, unsigned int n)
// print n bytes of raw data in hex format
{
#define maxNbytes 1024
   int i, j;
   unsigned char buf[3*maxNbytes+1];

   if (n>maxNbytes) n=maxNbytes;

   for (i=j=0; i<n; i++, j=j+3)
     sprintf(buf+j, "%02x ", rawbytes[i]);
   buf[j]=0;

   printf("0x%s\n", buf);
}

int main(int argc, char *argv[])
{
    RC4_KEY rc4key;
    unsigned int textlen;

    if (argc != 2)
    {
	printf("***usage: %s <plaintext>\n", argv[0]);
	exit(1);
    }
    textlen = strlen(argv[1]);
    if (textlen>=1024) textlen=1023;
    strncpy(plaintext, argv[1], textlen); plaintext[textlen]=0;

    printHexString(key, 8);
    printf("plaintext: '%s'\n", plaintext);
    RC4_set_key(&rc4key, strlen(key), key);
    RC4(&rc4key, textlen, plaintext,ciphertext);
    RC4_set_key(&rc4key, strlen(key), key);
    RC4(&rc4key, textlen, ciphertext, plaintext2);
    printf("plaintext2: '%s'\n", plaintext2);
    return 0;
}
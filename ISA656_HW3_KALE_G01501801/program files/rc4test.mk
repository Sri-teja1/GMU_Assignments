# rc4test.mk

CC = gcc
CFLAGS = -Wall -O2 -Imd5use  # Include md5use for header files
LIBS = -lssl -lcrypto

all: rc4test

rc4test: rc4test.o
	$(CC) $(CFLAGS) -o rc4test rc4test.o $(LIBS)

rc4test.o: rc4test.c
	$(CC) $(CFLAGS) -c rc4test.c

clean:
	rm -f *.o rc4test

CC = gcc
CFLAGS = -W -Wall -O2
VERSION="0.06"

all:	ckmd5

install:	all
	mkdir -p /usr/local/bin
	install ckmd5 /usr/local/bin/

clean:	
	rm -f ckmd5 configure.test *.o *~

ckmd5:	ckmd5.o md5c.o
	$(CC) $(CFLAGS) -o ckmd5 ckmd5.o md5c.o

ckmd5.o:	ckmd5.c md5.h
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" -c ckmd5.c

md5c.o:	md5.h md5c.c
	$(CC) $(CFLAGS) -c md5c.c


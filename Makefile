CC=gcc 
CFLAGS+=-lpcap 

all: wiretap

clean:
	-rm -rf wiretap wiretap.o

tar: wiretap.tar.gz

wiretap: wiretap.c
	gcc $^ ${CFLAGS} -o wiretap

wiretap.tar.gz: Makefile wiretap.c report.txt
	tar -zcvf $@ $^

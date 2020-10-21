CC=g++

all: sslsniff

sslsniff.o: sslsniff.cc sslsniff.h
	$(CC) -c sslsniff.cc -o $@

sslsniff: sslsniff.o
	$(CC) sslsniff.o -o $@ -lpcap

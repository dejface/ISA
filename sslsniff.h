/****************************************************************************/
/* File: sslsniff.h
/* Author: David Oravec (xorave05)
/* Description:
/*      - header file for sslsniff.cc with libraries, macros and function
/*        prototypes
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <getopt.h>
#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <netinet/ip6.h>
#include <string>
#include <iostream>
#include <list>

using namespace std;

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#define TLS_HEADER_LEN 5
#define SIZEOF_IPV6_HDR 40

/* struct which holds user params from commandline */
struct userArgs {
    const char* interface;
    const char* file;
    string ipClient, ipServer;
    int currentPacketSize;
    bool interfaceSet, fileSet, showDevices;
} userArgs;

typedef struct connectionInfo {
    string ipClient, ipServer, timestamp, hostname;
    long sec,usec;
    unsigned srcPort, dstPort;
    bool handshakeMadeClient, handshakeMade,dontWrite,hasHostname,finClient, finServer;
    int countOfPackets, length;
} connectionInfo;

void initStruct();
int parseArgs(int argc, char** argv);
void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer);
string getTimestamp(const u_char* Buffer, int Size, string state);
string getDest(const u_char* Buffer, size_t Size);
string getSource(const u_char* Buffer, size_t Size);
void endConnection(unsigned port, string lastTimestamp, struct tcphdr* tcph, const u_char* temp, size_t Size);
void processTCP(const u_char* Buffer, int Size, const struct pcap_pkthdr* header);
static int parseTLS(const u_char* Buffer, size_t Size, const struct pcap_pkthdr* header);
static int parse_extension(const uint8_t *Buffer, const uint8_t * temp, size_t Size, unsigned srcPort, unsigned dstPort, struct tcphdr* tcph);
static int parse_server_name_extension(const uint8_t *Buffer, const uint8_t * temp, size_t Size, unsigned srcPort, unsigned dstPort, struct tcphdr* tcph);

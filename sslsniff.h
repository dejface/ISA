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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
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
#define HEADER_LEN 54

void initStruct();
int parseArgs(int argc, char** argv);
void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer);
string getTimestamp(const u_char* Buffer, int Size, string state);
void printTCP(const u_char* Buffer, int Size);
static int parseTLS(const u_char* Buffer, size_t Size);
static int parse_extension(const uint8_t *Buffer, size_t Size);
static int parse_server_name_extension(const uint8_t *Buffer, size_t Size);
//int allocHostname(size_t len);]

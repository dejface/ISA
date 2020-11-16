/****************************************************************************/
/* File: sslsniff.cc
/* Author: David Oravec (xorave05)
/* Description:
/*      - simple programme for monitoring SSL connections
/*      - for more info run sudo ./sslsniff
*****************************************************************************/

#include "sslsniff.h"

struct hostent* he;
struct in_addr addr, addr2;
struct in6_addr addrIPV6, addrIPV6_2;
struct sockaddr_in source, dest;
struct sockaddr_in6 sourceIPV6, destIPV6;

/* global variables */
char tempBuf[256], buf[1024];
static int count = 0;
bool ipv6 = false; 
list<connectionInfo> listOfconn;
connectionInfo ci;
long secLast, usecLast;
_List_iterator<connectionInfo> temp_iterator;



/* initialization of struct */
void initStruct() {
    userArgs.interfaceSet = false;
    userArgs.fileSet = false;
}

/* Function in which argument parsing is being done*/

int parseArgs(int argc, char** argv) {
    int opt;
    char* endptr = NULL;
    opterr = 0;
    while ((opt = getopt(argc, argv, "i:r:")) != -1) {
        switch (opt) {
        case 'i': // interface option
            userArgs.interface = optarg;
            userArgs.interfaceSet = true;
            break;
        case 'r': // file option
            userArgs.file = optarg;
            userArgs.fileSet = true;
            break;
        case ':':
            break;

        default:
            userArgs.showDevices = true;
            if (optopt == 105) break;
            fprintf(stderr, "Wrong parameter!\n");
            return 1;
        }
    }
    return 0;
}

/* Callback function for incoming packets. Processing only TCP packets */

void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer) {

    const struct ether_header* ethernet_header; //ethernet header
    userArgs.currentPacketSize = header->len;
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ethernet_header = (struct ether_header*)(buffer);

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
        ipv6 = true;
    } else ipv6 = false;

    if (ipv6) {
        const struct ip6_hdr* ipv6Hdr;
        ipv6Hdr = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
        //TCP protocol ipv6
        if (ipv6Hdr->ip6_nxt == 6) processTCP(buffer, userArgs.currentPacketSize, header);
    } else {
        //TCP protocol ipv4
        if (iph->protocol == 6) processTCP(buffer, userArgs.currentPacketSize, header);
    }
}

/* Processing TCP packet and its size and headers */
void processTCP(const u_char* Buffer, int Size, const struct pcap_pkthdr* header) {

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short ip6hdrlen = 5 * 8;   // ipv6hdrlen
    struct tcphdr* tcph6 = (struct tcphdr*)(Buffer + ip6hdrlen + sizeof(struct ethhdr));
    
    if (ipv6){
        Size = Size - tcph6->doff * 4 - ip6hdrlen - 14;
    } else {
        Size = Size - tcph->doff * 4 - iphdrlen - 14;
    }
    
    parseTLS(Buffer, Size, header); 
}

/* Function which get a timestamp forms it for output and also stores
 * time in miliseconds for <duration> of SSL connection
 */
string getTimestamp(const u_char* Buffer, int Size, string state, const struct pcap_pkthdr* header) {

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short ip6hdrlen = 5 * 8;

    /* Getting timestamp and writing the header of packet*/
    struct timeval tv;
    time_t nowtime;
    struct tm* nowtm;

    nowtime = header->ts.tv_sec;
    nowtm = localtime(&header->ts.tv_sec);

    if (state == "actual"){
       ci.sec = header->ts.tv_sec;
       ci.usec = header->ts.tv_usec;
    } else if (state == "last"){
        secLast = header->ts.tv_sec;
        usecLast = header->ts.tv_usec;
    }

    strftime(tempBuf, sizeof(tempBuf), "%Y-%m-%d %H:%M:%S", nowtm);          // time is written to tempBuf
    snprintf(buf, sizeof(buf), "%s.%06ld,", tempBuf, header->ts.tv_usec);    // appending microseconds to tempBuf and storing it in buf
    return buf;   
}

/**
 * Function which returns source IP address
 */

string getSource(const u_char* Buffer, size_t Size){
    if (!ipv6) {
        struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
        unsigned short iphdrlen = sizeof(iph);
        
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
        source.sin_family = AF_INET;

        return inet_ntoa(source.sin_addr);
    } else {
        const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
        unsigned short ip6hdrlen = sizeof(ip6hdrlen);

        memset(&source, 0, sizeof(source));
        sourceIPV6.sin6_addr = ipv6Hdr->ip6_src;
        sourceIPV6.sin6_family = AF_INET6;
        char srcIPV6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6Hdr->ip6_src), srcIPV6, INET6_ADDRSTRLEN);
        srcIPV6[INET6_ADDRSTRLEN] = '\0';
        return srcIPV6;
    }
}

/**
 * Function which returns destination IP address
 */

string getDest(const u_char* Buffer, size_t Size){
    if (!ipv6) {
        struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
        unsigned short iphdrlen = sizeof(iph);

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;
        dest.sin_family = AF_INET;
        return inet_ntoa(dest.sin_addr);
    } else {
        const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
        unsigned short ip6hdrlen = sizeof(ip6hdrlen);

        memset(&dest, 0, sizeof(dest));
        destIPV6.sin6_addr = ipv6Hdr->ip6_dst;
        destIPV6.sin6_family = AF_INET6;
        char dstIPV6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6Hdr->ip6_dst), dstIPV6, INET6_ADDRSTRLEN);
        dstIPV6[INET6_ADDRSTRLEN] = '\0';
        return dstIPV6;
    }
}

/**
 * Function which prints out finished SSL connection and removes it from list of connections
 */
void endConnection(unsigned port, string lastTimestamp, struct tcphdr* tcph, const u_char* temp, size_t Size){
    for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
        //if both FINs were sent and handshake was made
        if (iterator->finClient && iterator->finServer && iterator->handshakeMade){ 
            if (iterator->dontWrite) continue;
            //counting duration
            long resultSec = secLast - iterator->sec;
            long resultUsec = usecLast - iterator->usec;
            if (resultUsec < 0){
                resultUsec = 1000000 + usecLast - iterator->usec;
                resultSec -= 1;
            }
            char tmpbf[100] = {0};
            snprintf(tmpbf, sizeof(tmpbf), "%ld.%06ld", resultSec, resultUsec);
            string final = iterator->timestamp + iterator->ipClient + "," + to_string(iterator->srcPort) + "," + 
                    iterator->ipServer + "," + iterator->hostname + "," + to_string(iterator->length) + "," + 
                    to_string(iterator->countOfPackets) + "," + tmpbf; 
            printf("%s\n", final.c_str());
            listOfconn.erase(iterator);
            return;
            //if both FINs were sent but handshake wasn't made -> set flag to true
        } else if (iterator->finClient && iterator->finServer && !iterator->handshakeMade){
            iterator->dontWrite = true;
        }
    }
}

/**
 * Fuction which finds appropriate connection in list of connections, 
 * stores iterator and returns true if success otherwise false
 */
bool check_connection(const u_char* temp, size_t Size, struct tcphdr* tcph){
    for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
        if (((getSource(temp,Size) == iterator->ipClient && 
            ntohs(tcph->source) == iterator->srcPort) &&
            (getDest(temp,Size) == iterator->ipServer &&
            ntohs(tcph->dest) == iterator->dstPort)) || 
            ((getSource(temp,Size) == iterator->ipServer && 
            ntohs(tcph->source) == iterator->dstPort) &&
            (getDest(temp,Size) == iterator->ipClient &&
            ntohs(tcph->dest) == iterator->srcPort))){
                temp_iterator = iterator;
                return true;
            }
    }
    return false;
}

/**
 * Function for parsing TLS packet
 * 
 */ 
static int parseTLS(const u_char* Buffer, size_t Size, const struct pcap_pkthdr* header){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short ip6hdrlen = 5 * 8;   // ipv6hdrlen
    struct tcphdr* tcph6 = (struct tcphdr*)(Buffer + ip6hdrlen + sizeof(struct ethhdr));

    const u_char* temp = Buffer;    //storing our buffer to temporary var
    int headerLen;
    if (ipv6) {
        headerLen = tcph6->doff * 4 + ip6hdrlen + 14;
    } else headerLen = tcph->doff * 4 + iphdrlen + 14;           // determine length of header
    Buffer += headerLen;
    size_t len;
    size_t pos = TLS_HEADER_LEN;
    int lngth = 0;

    if (ipv6) tcph = tcph6;
    if (tcph->syn && !tcph->ack && !tcph->fin) { 
        // if connection is already in list of structs, counting packets
        if (check_connection(temp, Size, tcph)) {
            temp_iterator->countOfPackets += 1;
        }
        // creating a new connetion and storing important stuff in list of structs
        ci.srcPort = ntohs(tcph->source);
        ci.dstPort = ntohs(tcph->dest);
        ci.ipClient = getSource(temp,Size);
        ci.ipServer = getDest(temp,Size);
        ci.timestamp = getTimestamp(temp, Size, "actual", header);
        ci.handshakeMade = false;
        ci.handshakeMadeClient = false;
        ci.finServer = false;
        ci.finClient = false;
        ci.countOfPackets = 1;
        listOfconn.push_back(ci);
    } else if (tcph->syn && tcph->ack && !tcph->fin){
        // if connection is already in list of structs, counting packets
        if (check_connection(temp, Size, tcph)) {
            temp_iterator->countOfPackets += 1;
        }
    } else if (!tcph->syn && tcph->ack && !tcph->fin && !tcph->rst){
        // if connection is already in list of structs, counting packets
        if (check_connection(temp, Size, tcph)) {
            temp_iterator->countOfPackets += 1;
        }
    } else if (tcph->fin) {
       if ((userArgs.currentPacketSize - headerLen) < TLS_HEADER_LEN){
           for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
            if (((getSource(temp,Size) == iterator->ipClient && 
                ntohs(tcph->source) == iterator->srcPort) &&
                (getDest(temp,Size) == iterator->ipServer &&
                ntohs(tcph->dest) == iterator->dstPort))){
                iterator->finClient = true;     //fin from client
                iterator->countOfPackets += 1;
                break;
            }
            else if (((getSource(temp,Size) == iterator->ipServer && 
                ntohs(tcph->source) == iterator->dstPort) &&
                (getDest(temp,Size) == iterator->ipClient &&
                ntohs(tcph->dest) == iterator->srcPort))){
                iterator->finServer = true;     //fin from server
                iterator->countOfPackets += 1;
                break;
            }
        }
        //ending and printing connection
        string lastTimestamp = getTimestamp(temp, Size, "last", header);
        endConnection(ntohs(tcph->source), lastTimestamp, tcph, temp, Size);
       }
    } else if (tcph->rst){
        if (check_connection(temp, Size, tcph)) {
            temp_iterator->finClient = true;
            temp_iterator->finServer = true;
            temp_iterator->countOfPackets += 1;
        }
        string lastTimestamp = getTimestamp(temp, Size, "last", header);
        endConnection(ntohs(tcph->source), lastTimestamp, tcph, temp, Size);
       // return 0;
    } else {
        // if connection is already in list of structs, counting packets
        for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
            if (((getSource(temp,Size) == iterator->ipClient && 
                ntohs(tcph->source) == iterator->srcPort) &&
                (getDest(temp,Size) == iterator->ipServer &&
                ntohs(tcph->dest) == iterator->dstPort))){
                    iterator->countOfPackets += 1;
                    break;
                } 
            else if(((getSource(temp,Size) == iterator->ipServer && 
                ntohs(tcph->source) == iterator->dstPort) &&
                (getDest(temp,Size) == iterator->ipClient &&
                ntohs(tcph->dest) == iterator->srcPort))){
                    iterator->countOfPackets += 1;
                break;
            }
        }
    }

    if ((userArgs.currentPacketSize - headerLen) < TLS_HEADER_LEN) return 1;

    // check the first byte of payload
    switch (Buffer[0]){
        case 0x16:
            if (Buffer[1] == 0x03){
                if (Buffer[2] == 0x00 || Buffer[2] == 0x01 || Buffer[2] == 0x02
                    || Buffer[2] == 0x03 || Buffer[2] == 0x04){
                        //if TLS header meets conditions, we can continue
                        if (Buffer[5] == 0x01){ //client hello
                            // if connection is already in list of structs, set flag of handshake, counting length of SSL connection
                            for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                                if (((getSource(temp,Size) == iterator->ipClient && 
                                    ntohs(tcph->source) == iterator->srcPort) &&
                                    (getDest(temp,Size) == iterator->ipServer &&
                                    ntohs(tcph->dest) == iterator->dstPort))){

                                    iterator->length = (ntohs(Buffer[3]) + Buffer[4]);
                                    iterator->handshakeMadeClient = true;
                                    lngth = (ntohs(Buffer[3]) + Buffer[4]);
                                    break;
                                }
                            } 
                        } else if (Buffer[5] == 0x02) { //server hello
                            // if connection is already in list of structs, confirms handshake, counting packets and length of SSL connection
                            if (check_connection(temp, Size, tcph)) {
                                if (temp_iterator->handshakeMadeClient){
                                    temp_iterator->handshakeMade = true;
                                    temp_iterator->length += (ntohs(Buffer[3]) + Buffer[4]);
                                    lngth = (ntohs(Buffer[3]) + Buffer[4]);
                                }
                            }
                        } else {
                            // if connection is already in list of structs, counting length of SSL connection
                            if (check_connection(temp, Size, tcph)) {
                                if (temp_iterator->handshakeMadeClient){
                                    temp_iterator->length += (ntohs(Buffer[3]) + Buffer[4]);
                                    lngth = (ntohs(Buffer[3]) + Buffer[4]);
                                }
                            }
                        }
                        // go through the whole packet and check if another TLS headers are included
                        for (int i = lngth + headerLen + TLS_HEADER_LEN; i < userArgs.currentPacketSize; i++){
                            if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                                if (temp[i+1] == 0x03){
                                    if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                                        || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                                        if (check_connection(temp, Size, tcph)) {
                                            if (temp_iterator->handshakeMade){
                                                lngth = (ntohs(temp[i+3]) + temp[i+4]);
                                                temp_iterator->length += (ntohs(temp[i+3]) + temp[i+4]);
                                                i += TLS_HEADER_LEN + lngth - 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        fprintf(stderr, "This protocol isn't supported in TLS.\n");
                        return EXIT_FAILURE;
                    }
            } 
            break;
        case 0x14:
        case 0x15:    
        case 0x17:
            if (Buffer[1] == 0x03){
                if (Buffer[2] == 0x00 || Buffer[2] == 0x01 || Buffer[2] == 0x02
                    || Buffer[2] == 0x03 || Buffer[2] == 0x04) {
                    // if connection is already in list of structs, counting length of SSL connection
                    if (check_connection(temp, Size, tcph)) {
                        if (temp_iterator->handshakeMade){
                            temp_iterator->length += (ntohs(Buffer[3]) + Buffer[4]);
                            lngth = (ntohs(Buffer[3]) + Buffer[4]);
                        }
                    }
                } 
            }
            // go through the whole packet and check if another TLS headers are included
            for (int i = headerLen + TLS_HEADER_LEN + lngth; i < userArgs.currentPacketSize; i++){
                if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                    if (temp[i+1] == 0x03){
                        if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                            || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                            // if connection is already in list of structs, counting length of SSL connection
                            if (check_connection(temp, Size, tcph)) {
                                if (temp_iterator->handshakeMade){
                                    lngth = (ntohs(temp[i+3]) + temp[i+4]);
                                    temp_iterator->length += (ntohs(temp[i+3]) + temp[i+4]);
                                    i += TLS_HEADER_LEN + lngth - 1;
                                }
                            }
                        }
                    }
                }
            }
            break;
        default:
            // specific scenario especially for reassembled packets which are too big
            // jumping through payload from TLS header + length of SSL connection in bytes
            for (int i = 0; i < userArgs.currentPacketSize; i++){
                if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                    if (temp[i+1] == 0x03){
                        if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                            || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                            if (check_connection(temp, Size, tcph)) {
                                if (temp_iterator->handshakeMade){
                                    lngth = (ntohs(temp[i+3]) + temp[i+4]);
                                    temp_iterator->length += (ntohs(temp[i+3]) + temp[i+4]);
                                    i += TLS_HEADER_LEN + lngth - 1;
                                }
                            }
                        }
                    }
                }
            }
    }       

    // if the FIN flag is included
    if (tcph->fin) {
        for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
            if (((getSource(temp,Size) == iterator->ipClient && 
                ntohs(tcph->source) == iterator->srcPort) &&
                (getDest(temp,Size) == iterator->ipServer &&
                ntohs(tcph->dest) == iterator->dstPort))){
                iterator->finClient = true;     //fin from client
                iterator->countOfPackets += 1;
                break;
            }
            else if (((getSource(temp,Size) == iterator->ipServer && 
                ntohs(tcph->source) == iterator->dstPort) &&
                (getDest(temp,Size) == iterator->ipClient &&
                ntohs(tcph->dest) == iterator->srcPort))){
                iterator->finServer = true;     //fin from server
                iterator->countOfPackets += 1;
                break;
            }
        }
        //ending and printing connection
        string lastTimestamp = getTimestamp(temp, Size, "last", header);
        endConnection(ntohs(tcph->source), lastTimestamp, tcph, temp, Size);
    }

    /* Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
     * All rights reserved.
     *
     * Redistribution and use in source and binary forms, with or without
     * modification, are permitted provided that the following conditions are met:
     *
     * 1. Redistributions of source code must retain the above copyright notice,
     *    this list of conditions and the following disclaimer.
     * 2. Redistributions in binary form must reproduce the above copyright
     *    notice, this list of conditions and the following disclaimer in the
     *    documentation and/or other materials provided with the distribution.
     *
     * Following snippet of code for parsing SNI from packet was borrowed from
     * Dustin Lundquist from his tls.c module.
     * Code was modified for my purposes and license terms are included in documentation.
     * URL website of tls.c: https://github.com/dlundquist/sniproxy/blob/master/src/tls.c
     */

    len = ((size_t)Buffer[3] << 8) +
        (size_t)Buffer[4] + TLS_HEADER_LEN;
    Size = MIN(Size, len);

    /* Check we received entire TLS record length */
    if (Size < len)
        return 1;

    /*
     * Handshake
     */
    if (pos + 1 > Size) {
        return 1;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > Size)
        return 1;
    len = (size_t)Buffer[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > Size)
        return 1;
    len = ((size_t)Buffer[pos] << 8) + (size_t)Buffer[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > Size)
        return 1;
    len = (size_t)Buffer[pos];
    pos += 1 + len;

    /* Extensions */
    if (pos + 2 > Size)
        return 1;
    len = ((size_t)Buffer[pos] << 8) + (size_t)Buffer[pos + 1];
    pos += 2;

    if (pos + len > Size)
        return 1;
    return parse_extension(Buffer + pos, temp, len, ntohs(tcph->source), ntohs(tcph->dest), tcph);

}

static int parse_extension(const uint8_t *Buffer,const uint8_t * temp, size_t Size, unsigned srcPort, unsigned dstPort, struct tcphdr* tcph){
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= Size) {
        /* Extension Length */
        len = ((size_t)Buffer[pos + 2] << 8) +
            (size_t)Buffer[pos + 3];

        /* Check if it's a server name extension */
        if (Buffer[pos] == 0x00 && Buffer[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > Size)
                return 1;
            return parse_server_name_extension(Buffer + pos + 4, temp, len, srcPort, dstPort, tcph);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != Size)
        return 1;

    return 1;

}

static int parse_server_name_extension(const uint8_t *Buffer, const uint8_t * temp, size_t Size, unsigned srcPort, unsigned dstPort, struct tcphdr* tcph){
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < Size) {
        len = ((size_t)Buffer[pos + 1] << 8) +
            (size_t)Buffer[pos + 2];

        if (pos + 3 + len > Size)
            return 1;

        switch (Buffer[pos]) { /* name type */
            case 0x00: /* host_name */
                if (check_connection(temp, Size, tcph)){
                    if (!temp_iterator->hasHostname){
                            temp_iterator->hostname = (const char *)(Buffer + pos + 3);
                            (temp_iterator->hostname)[len] = '\0';
                            temp_iterator->hasHostname = true;
                        }
                }
                return len;
            default:
                ;
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != Size)
        return 1;

    return 1;
}

int main(int argc, char** argv){
    initStruct();
    int errCode = 0;
    if (errCode = parseArgs(argc,argv)) return errCode;
    
    char error[PCAP_ERRBUF_SIZE];       // buffer for error messages
    pcap_if_t* interfaces, * temp;
    struct bpf_program fp;
    bpf_u_int32 mask;		            // netmask of our sniffing device
    bpf_u_int32 net;
    int countOfInterface = 0, i = 0;

    // finds all interfaces on system
    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("Error in pcap_findalldevs\n");
        return EXIT_FAILURE;
    }

    if (!userArgs.interfaceSet && !userArgs.fileSet && !userArgs.showDevices){
        printf("SSL sniffer\n"
               "Usage: sudo ./sslsniff [-i interface] [-r file]\n"
               "-i interface - sniffer will listen on chosen interface\n"
               "-r file - file in pcapng format\n"
               "no options - shows this help\n");
        return 1;
    } 

    /*  - loop through found interfaces, if interface is matched with user
          defined interface, breaks the loop and continue in code
        - if none of interfaces match with user defined interface, error is raised
        - if user doesn't specify interface, all of system interfaces are written to
          stdout and program ends with EXIT_SUCCESS
    */
    if (!userArgs.fileSet) {
        for (temp = interfaces; temp; temp = temp->next) {
            if (userArgs.interfaceSet) {
                if (strcmp(userArgs.interface, temp->name) == 0) {
                    countOfInterface++;
                    break;
                }

                if ((countOfInterface == 0) && (temp->next == NULL)) {
                    fprintf(stderr, "No valid interface was found!\n");
                    return EXIT_FAILURE;
                }
            }
            else {
                printf("%d. %s", ++i, temp->name);
                if (temp->description)
                    printf(" (%s)\n", temp->description);
                else
                    printf(" (No description available)\n");

                if ((temp->next == NULL) && (countOfInterface == 0))
                    return 0;
            }
        }
    }

    if ((userArgs.interfaceSet && userArgs.fileSet) || 
        (userArgs.interfaceSet && !userArgs.fileSet)){
        pcap_t* dev = pcap_open_live(userArgs.interface, BUFSIZ, 0, 0, error);
        if (!dev) {
            fprintf(stderr, "Opening of device %s wasn't successful. Error: %s \n", userArgs.interface, error);
            return EXIT_FAILURE;
        }
        pcap_loop(dev, 0, processPacket, NULL);
        pcap_close(dev);
    } else if (!userArgs.interfaceSet && userArgs.fileSet){
        pcap_t* dev = pcap_open_offline(userArgs.file, error);
        if (!dev) {
            fprintf(stderr, "Opening of device %s wasn't successful. Error: %s \n", userArgs.interface, error);
            return EXIT_FAILURE;
        }
        pcap_loop(dev, 0, processPacket, NULL);
        pcap_close(dev);
    }
    return EXIT_SUCCESS;
}

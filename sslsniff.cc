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
static int len = 0;


/* initialization of struct */
void initStruct() {
    userArgs.interfaceSet = false;
    userArgs.fileSet = false;
}

int parseArgs(int argc, char** argv) {
    int opt;
    char* endptr = NULL;
    opterr = 0;
    while ((opt = getopt(argc, argv, "i:r:")) != -1) {
        switch (opt) {
            // interface option
        case 'i':
            userArgs.interface = optarg;
            userArgs.interfaceSet = true;
            break;
        case 'r':
            userArgs.file = optarg;
            userArgs.fileSet = true;
            //printf("%s", userArgs.file);
            break;
        case ':':
            printf("%d",opt);
            //printf("%d", optopt);

        default:
            fprintf(stderr, "Wrong parameter!\n");
            return 1;
        }
    }
    if (!userArgs.interfaceSet && !userArgs.fileSet){
        printf("SSL sniffer\n"
               "Usage: sudo ./sslsniff [-i interface] [-r file]\n"
               "-i interface - sniffer will listen on this interface\n"
               "-r file - file in pcapng format\n"
               "no options - shows this help\n");
        return 1;
    } else return 0;
}

void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer) {

    const struct ether_header* ethernet_header; //ethernet header
    userArgs.currentPacketSize = header->len;
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ethernet_header = (struct ether_header*)(buffer);

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
        ipv6 = true;
    }

    /*if (ipv6) {
        const struct ip6_hdr* ipv6Hdr;
        ipv6Hdr = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
        int protocol = ipv6Hdr->ip6_nxt;

        if (protocol == 6) {            //TCP protocol
            printTCP(buffer, userArgs.currentPacketSize, header);
        }

    } else {*/

        switch (iph->protocol) //Check the Protocol and do accordingly...
        {
        case 6:  //TCP Protocol
            printTCP(buffer, userArgs.currentPacketSize,header);
            //break;

        default:
            break;
        //}
    }
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

    //gettimeofday(&tv, NULL);
    nowtime = header->ts.tv_sec;
    nowtm = localtime(&header->ts.tv_sec);

    if (state == "actual"){
        ci.sec = (header->ts.tv_sec * 1000 + header->ts.tv_usec/1000.0);
    } else if (state == "last"){
        secLast =  (header->ts.tv_sec * 1000 + header->ts.tv_usec/1000.0);

    }

    strftime(tempBuf, sizeof(tempBuf), "%Y-%m-%d %H:%M:%S", nowtm);          // time is written to tempBuf
    snprintf(buf, sizeof(buf), "%s.%06ld,", tempBuf, header->ts.tv_usec);    // appending microseconds to tempBuf and storing it in buf
    return buf;

    /* Getting hostname for ipv6 IP address */
   /* if (ipv6) {
        memset(&source, 0, sizeof(source));
        sourceIPV6.sin6_addr = ipv6Hdr->ip6_src;

        memset(&dest, 0, sizeof(dest));
        destIPV6.sin6_addr = ipv6Hdr->ip6_dst;

        sourceIPV6.sin6_family = AF_INET6;
        destIPV6.sin6_family = AF_INET6;

        addrIPV6 = sourceIPV6.sin6_addr;
        addrIPV6_2 = destIPV6.sin6_addr;

        snprintf(tempBuf, sizeof(tempBuf), "%s", buf);
        memset(buf, 0, sizeof(buf));

        if (he = (gethostbyaddr((const void*)&addrIPV6, sizeof(addrIPV6), AF_INET6)))
            snprintf(buf, sizeof(buf), "%s %s :", tempBuf, he->h_name);
        else {
            char srcIPV6[INET_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6Hdr->ip6_src), srcIPV6, INET6_ADDRSTRLEN);
            snprintf(buf, sizeof(buf), "%s %s :", tempBuf, srcIPV6);
        }

        he = 0;
        memset(tempBuf, 0, sizeof(tempBuf));

        if (he = (gethostbyaddr((const void*)&addrIPV6_2, sizeof(addrIPV6_2), AF_INET6)))
            snprintf(tempBuf, sizeof(tempBuf), "%s :", he->h_name);
        else {
            char dstIPV6[INET_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6Hdr->ip6_dst), dstIPV6, INET6_ADDRSTRLEN);
            snprintf(tempBuf, sizeof(tempBuf), "%s :", dstIPV6);
        }

    }*/
}

/**
 * Function which returns source IP address
 */

string getSource(const u_char* Buffer, size_t Size){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    source.sin_family = AF_INET;

    return inet_ntoa(source.sin_addr);
}

/**
 * Function which returns destination IP address
 */

string getDest(const u_char* Buffer, size_t Size){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    dest.sin_family = AF_INET;
    return inet_ntoa(dest.sin_addr);
}

/**
 * Function which prints out finished SSL connection and removes it from list of connections
 */
void endConnection(unsigned port, string lastTimestamp, struct tcphdr* tcph, const u_char* temp, size_t Size){
    for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
       /*if (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
            ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort){  */ 
            if (iterator->finCount == 2){
                double resultusec = secLast - iterator->sec;
                char tmpbf[100] = {0};
                snprintf(tmpbf, sizeof(tmpbf), "%.6f",resultusec/1000);
                string final = iterator->timestamp + iterator->ipClient + "," + to_string(iterator->srcPort) + "," + 
                        iterator->ipServer + "," + iterator->hostname + "," + to_string(iterator->length) + "," + 
                        to_string(iterator->countOfPackets) + "," + tmpbf; 
                printf("%s\n", final.c_str());
                listOfconn.erase(iterator);
                return;
            //}
        }
    }
}

/**
 * Function for parsing TLS packet
 * 
 */ 
static int parseTLS(const u_char* Buffer, size_t Size, const struct pcap_pkthdr* header){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    const u_char* temp = Buffer;    //storing our buffer to temporary var
    int headerLen = tcph->doff * 4 + iphdrlen + 14;           //skip headers of Ethernet/ip/tcp
    Buffer += headerLen;
    size_t len;
    size_t pos = TLS_HEADER_LEN;

    //ending a connection if TCP FIN flag is included in packet
    if (tcph->fin) {
        if (Size < TLS_HEADER_LEN){
            for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                if (((getSource(temp,Size) == iterator->ipClient && 
                    ntohs(tcph->source) == iterator->srcPort) &&
                    (getDest(temp,Size) == iterator->ipServer &&
                    ntohs(tcph->dest) == iterator->dstPort)) || 
                    ((getSource(temp,Size) == iterator->ipServer && 
                    ntohs(tcph->source) == iterator->dstPort) &&
                    (getDest(temp,Size) == iterator->ipClient &&
                    ntohs(tcph->dest) == iterator->srcPort))){
                    iterator->finCount++;
                    break;
                }
            } 
            string lastTimestamp = getTimestamp(temp, Size, "last", header);
            endConnection(ntohs(tcph->source), lastTimestamp, tcph, temp, Size);
        }
    }

    if (Size < TLS_HEADER_LEN){
        return -1;
    }
    if(ntohs(tcph->source) == 59120 || ntohs(tcph->dest) == 59120){
        int a = 1;
    }
    switch (Buffer[0]){
        case 0x16:
            if (Buffer[1] == 0x03){
                if (Buffer[2] == 0x00 || Buffer[2] == 0x01 || Buffer[2] == 0x02
                    || Buffer[2] == 0x03 || Buffer[2] == 0x04){
                        if (Buffer[5] == 0x01){
                            ci.srcPort = ntohs(tcph->source);
                            ci.dstPort = ntohs(tcph->dest);
                            ci.ipClient = getSource(temp,Size);
                            ci.ipServer = getDest(temp,Size);
                            ci.length = (ntohs(Buffer[3]) + Buffer[4]);
                            ci.timestamp = getTimestamp(temp, Size, "actual", header);
                            ci.countOfPackets = 1;
                            ci.handshakeMade = false;
                            if(ntohs(tcph->source) == 50280 || ntohs(tcph->dest) == 50280){
                                        int a = 1;
                                    }
                            ci.finCount = 0;
                            ci.wasHere = false;
                            len = (ntohs(Buffer[3]) + Buffer[4]);
                            listOfconn.push_back(ci);
                        } else if (Buffer[5] == 0x02) {
                            for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                                if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                                    ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                                    (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                                    ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){
                                    if(ntohs(tcph->source) == 59120 || ntohs(tcph->dest) == 59120){
                                        int a = 1;
                                    }
                                    iterator->length += (ntohs(Buffer[3]) + Buffer[4]);
                                    iterator->countOfPackets += 1;
                                    iterator->handshakeMade = true;
                                    len = (ntohs(Buffer[3]) + Buffer[4]);
                                    break;
                                
                                }
                            }
                        } else {
                            for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                                if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                                    ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                                    (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                                    ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){
                                    if (iterator->handshakeMade){
                                    if(ntohs(tcph->source) == 50280 || ntohs(tcph->dest) == 50280){
                                        int a = 1;
                                    }
                                        if (iterator->wasHere) iterator->wasHere = false;
                                        iterator->length += (ntohs(Buffer[3]) + Buffer[4]);
                                        iterator->countOfPackets += 1;
                                        len = (ntohs(Buffer[3]) + Buffer[4]);
                                    }
                                } 
                            }
                        }
                       /* for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                            if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                                ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                                (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                                ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){
                                    int len = iterator->length;
                                    break;
                            }
                        }*/
                        for (int i = headerLen + TLS_HEADER_LEN + len; i < userArgs.currentPacketSize; i++){
                            if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                                if (temp[i+1] == 0x03){
                                    if (temp[i+2] == 0x00 || temp[i+2] == 0x02
                                        || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                                            for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                                                if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                                                    ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                                                    (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                                                    ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){ 
                                                                                        if(ntohs(tcph->source) == 50280 || ntohs(tcph->dest) == 50280){
                                        int a = 1;
                                    }       
                                                    
                                                    if (iterator->handshakeMade) {
                                                        if (iterator->wasHere) iterator->wasHere = false;
                                                        len = (ntohs(temp[i+3]) + temp[i+4]);
                                                        iterator->length += (ntohs(temp[i+3]) + temp[i+4]);
                                                    }
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
                    for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                        if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                            ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                            (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                            ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){
                            if (iterator->handshakeMade){
                                                                    if(ntohs(tcph->source) == 50280 || ntohs(tcph->dest) == 50280){
                                        int a = 1;
                                    }
                                if (iterator->wasHere) iterator->wasHere = false;
                                iterator->length += (ntohs(Buffer[3]) + Buffer[4]);
                                iterator->countOfPackets += 1;
                                len = (ntohs(Buffer[3]) + Buffer[4]);
                            }
                        }
                    }
                } 
            }
            for (int i = headerLen + TLS_HEADER_LEN + len; i < userArgs.currentPacketSize; i++){
                if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                    if (temp[i+1] == 0x03){
                        if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                            || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                                for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                                    if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                                        ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                                        (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                                        ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){
                                                                            if(ntohs(tcph->source) == 50280 || ntohs(tcph->dest) == 50280){
                                        int a = 1;
                                    }
                                        if (iterator->handshakeMade) {
                                            if (iterator->wasHere) iterator->wasHere = false;
                                            len = (ntohs(temp[i+3]) + temp[i+4]);
                                            iterator->length += (ntohs(temp[i+3]) + temp[i+4]);
                                        }
                                    } 
                                }
                        }
                    }
                }
            }
            break;
        default:
            for (int i = headerLen + TLS_HEADER_LEN; i < userArgs.currentPacketSize; i++){
                if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                    if (temp[i+1] == 0x03){
                        if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                            || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                                for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                                    if ((getSource(temp,Size) == iterator->ipClient && getDest(temp,Size) == iterator->ipServer &&
                                        ntohs(tcph->source) == iterator->srcPort && ntohs(tcph->dest) == iterator->dstPort) || 
                                        (getSource(temp,Size) == iterator->ipServer && getDest(temp,Size) == iterator->ipClient &&
                                        ntohs(tcph->source) == iterator->dstPort && ntohs(tcph->dest) == iterator->srcPort)){
                                                                                if(ntohs(tcph->source) == 50280 || ntohs(tcph->dest) == 50280){
                                        int a = 1;
                                    }
                                        
                                        if (iterator->handshakeMade) {
                                            len = (ntohs(temp[i+3]) + temp[i+4]);
                                            iterator->length += (ntohs(temp[i+3]) + temp[i+4]);
                                            if (!iterator->wasHere || (iterator->wasHere && len > userArgs.currentPacketSize)) {
                                                iterator->wasHere = true;
                                                iterator->countOfPackets += 1;
                                            }
                                        }
                                    } 
                                }
                        }
                    }
                }
            }
    }       

    if (tcph->fin) {
        for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
            if (((getSource(temp,Size) == iterator->ipClient && 
                ntohs(tcph->source) == iterator->srcPort) &&
                (getDest(temp,Size) == iterator->ipServer &&
                ntohs(tcph->dest) == iterator->dstPort)) || 
                ((getSource(temp,Size) == iterator->ipServer && 
                ntohs(tcph->source) == iterator->dstPort) &&
                (getDest(temp,Size) == iterator->ipClient &&
                ntohs(tcph->dest) == iterator->srcPort))){
                iterator->finCount++;
                break;
            }
        } 
        string lastTimestamp = getTimestamp(temp, Size, "last", header);
        endConnection(ntohs(tcph->source), lastTimestamp, tcph, temp, Size);
    }

    len = ((size_t)Buffer[3] << 8) +
        (size_t)Buffer[4] + TLS_HEADER_LEN;
    Size = MIN(Size, len);

    /* Check we received entire TLS record length */
    if (Size < len)
        return -1;

    /*
     * Handshake
     */
    if (pos + 1 > Size) {
        return -5;
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
        return -5;
    len = (size_t)Buffer[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > Size)
        return -5;
    len = ((size_t)Buffer[pos] << 8) + (size_t)Buffer[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > Size)
        return -5;
    len = (size_t)Buffer[pos];
    pos += 1 + len;

    /* Extensions */
    if (pos + 2 > Size)
        return -5;
    len = ((size_t)Buffer[pos] << 8) + (size_t)Buffer[pos + 1];
    pos += 2;

    if (pos + len > Size)
        return -5;
    return parse_extension(Buffer + pos, len, ntohs(tcph->source), ntohs(tcph->dest));

}

static int parse_extension(const uint8_t *Buffer, size_t Size, unsigned srcPort, unsigned dstPort){
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
                return -5;
            return parse_server_name_extension(Buffer + pos + 4, len, srcPort, dstPort);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != Size)
        return -5;

    return -2;

}

static int parse_server_name_extension(const uint8_t *Buffer, size_t Size, unsigned srcPort, unsigned dstPort){
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < Size) {
        len = ((size_t)Buffer[pos + 1] << 8) +
            (size_t)Buffer[pos + 2];

        if (pos + 3 + len > Size)
            return -5;

        switch (Buffer[pos]) { /* name type */
            case 0x00: /* host_name */
                               
                for (auto iterator = listOfconn.begin(); iterator != listOfconn.end(); iterator++){
                    if (srcPort == iterator->srcPort || dstPort == iterator->srcPort){
                        iterator->hostname = (const char *)(Buffer + pos + 3);
                        (ci.hostname)[len] = '\0';
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
        return -5;

    return -2;
}


/* Function which prints header of IPK project and TCP packet*/
void printTCP(const u_char* Buffer, int Size, const struct pcap_pkthdr* header) {

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short ip6hdrlen = 5 * 8;   // ipv6hdrlen
    struct tcphdr* tcph6 = (struct tcphdr*)(Buffer + ip6hdrlen + sizeof(struct ethhdr));

    Size = Size - tcph->doff * 4 - iphdrlen - 14;

    parseTLS(Buffer, Size, header);
    /*char finalBuf[2048];
    if (ipv6) {
        snprintf(finalBuf, sizeof(finalBuf), "%s %u > %s %u", buf, ntohs(tcph6->source), tempBuf, ntohs(tcph6->dest));
        printf("%s\n\n", finalBuf);
        int hdrlen = ip6hdrlen + 14 + tcph6->doff * 4;
        //dataFlush(Buffer, Size, hdrlen);
    }*/
    //else {
        /*if (!hostnameFound)
            snprintf(finalBuf, sizeof(finalBuf), "%s,%u,%s,%u", buf, ntohs(tcph->source), tempBuf, ntohs(tcph->dest));
        else {
            snprintf(finalBuf, sizeof(finalBuf), "%s,%u,%s,%s,%u", buf, ntohs(tcph->source), tempBuf, userArgs.hostname.c_str(), ntohs(tcph->dest));
            hostnameFound = false;
        }
        printf("%s\n\n", finalBuf);
        int hdrlen = iphdrlen + 14 + tcph->doff * 4;
        //dataFlush(Buffer, Size, hdrlen);*/
    //}
   /* if (connectionInfo.closed) {
        string final = connectionInfo.timestamp + connectionInfo.ipClient + "," + to_string(connectionInfo.port) + "," + \ 
                        connectionInfo.hostname + "," + to_string(connectionInfo.countOfPackets); 
        printf("%s\n", final.c_str());
        connectionInfo.closed = false;
        connectionInfo.countOfPackets = 0;
    }*/
    //printf("%s", Buffer);
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

    /*  - loop through found interfaces, if interface is matched with user
          defined interface, breaks the loop and continue in code
        - if none of interfaces match with user defined interface, error is raised
        - if user doesn't specify interface, all of system interfaces are written to
          stdout and program ends with EXIT_SUCCESS
    */
    if (userArgs.interfaceSet){
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
    /* File name: sniffer.c
     * Author: Copyright (c) 2002 Tim Carstens
     * Date: 2002-01-07
     * Author's description: Demonstration of using libpcap
     * From website: tcpdump.org/sniffex.c
     *
     * My commentary: All rights reserved Tim Carstens
     *                Following fragment of code was borrowed from https://www.tcpdump.org/pcap.html ,
     *                but it's property of Tim Carstens
     *                Code was modified just a little for project purposes
     */

    if (userArgs.interfaceSet && userArgs.fileSet){

    } else if (userArgs.interfaceSet && !userArgs.fileSet){
        pcap_t* dev = pcap_open_live(userArgs.interface, BUFSIZ, 0, 0, error);
        if (!dev) {
            fprintf(stderr, "Opening of device %s wasn't successful. Error: %s \n", userArgs.interface, error);
            return EXIT_FAILURE;
        }
        pcap_loop(dev, 0, processPacket, NULL);
        pcap_close(dev);
    } else if (!userArgs.interfaceSet && userArgs.fileSet){
        //pcap_t* dev = pcap_open_offline(userArgs.file, error);
        pcap_t* dev = pcap_open_offline("/home/student/Desktop/isa/hardcore.pcapng", error);
        if (!dev) {
            fprintf(stderr, "Opening of device %s wasn't successful. Error: %s \n", userArgs.interface, error);
            return EXIT_FAILURE;
        }
        pcap_loop(dev, 0, processPacket, NULL);
        pcap_close(dev);
    }
    // opening specified device for sniffing

    // loop with a callback function
    /*pcap_loop(dev, 0, processPacket, NULL);
    pcap_close(dev);*/
    return EXIT_SUCCESS;
}

#include "sslsniff.h"

struct hostent* he;
struct in_addr addr, addr2;
struct in6_addr addrIPV6, addrIPV6_2;
struct sockaddr_in source, dest;
struct sockaddr_in6 sourceIPV6, destIPV6;
//char **hostname;
bool hostnameFound = false;

/* global variables */
char tempBuf[256], buf[1024];
static int count = 0;
bool ipv6 = false; 
static bool serverHandshake = false;  

/* struct which holds user params from commandline */
struct userArgs {
    string interface;
    string file;
    string ipClient, ipServer;
    int currentPacketSize;
    bool interfaceSet;
    bool fileSet;
} userArgs;

typedef struct connectionInfo{
    string ipClient, ipServer, timestamp, hostname;
    long sec,usec;
    unsigned port;
    bool handshakeMade, closed;
    int countOfPackets, length;
} connectionInfo;

connectionInfo ci, ciPrev, ciLast;
/* initialization of struct */
void initStruct() {
    //userArgs.interface = "";
    //userArgs.file = "";
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

    if (ipv6) {
        const struct ip6_hdr* ipv6Hdr;
        ipv6Hdr = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
        int protocol = ipv6Hdr->ip6_nxt;

        if (protocol == 6) {            //TCP protocol
            printTCP(buffer, userArgs.currentPacketSize);
        }

    } else {

        switch (iph->protocol) //Check the Protocol and do accordingly...
        {
        case 6:  //TCP Protocol
            printTCP(buffer, userArgs.currentPacketSize);
            break;

        default:
            break;
        }
    }
}

/* Function which get a timestamp and forms a header for our IPK project
 * Format: timestamp IP/HOSTNAME : SOURCE_PORT > IP/HOSTNAME : DEST_PORT
 */
string getTimestamp(const u_char* Buffer, int Size, string state) {

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short ip6hdrlen = 5 * 8;

    /* Getting timestamp and writing the header of packet*/
    struct timeval tv;
    time_t nowtime;
    struct tm* nowtm;

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);

    if (state == "prev"){
        ciPrev.sec = tv.tv_sec;
        ciPrev.usec = tv.tv_usec;
    } else if (state == "actual"){
        ci.sec = tv.tv_sec;
        ci.usec = tv.tv_usec;
    } else if (state == "last"){
        ciLast.sec = tv.tv_sec;
        ciLast.usec = tv.tv_usec;
    }

    strftime(tempBuf, sizeof(tempBuf), "%Y-%m-%d %H:%M:%S", nowtm);          // time is written to tempBuf
    snprintf(buf, sizeof(buf), "%s.%06ld,", tempBuf, tv.tv_usec);    // appending microseconds to tempBuf and storing it in buf
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

    } else {
        /* Get host name, if it is not possible, ip will be written*/
       /* memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        source.sin_family = AF_INET;
        dest.sin_family = AF_INET;

        addr = source.sin_addr;
        addr2 = dest.sin_addr;

        snprintf(tempBuf, sizeof(tempBuf), "%s", buf);
        memset(buf, 0, sizeof(buf));

        snprintf(buf, sizeof(buf), "%s%s", tempBuf, inet_ntoa(source.sin_addr));

        he = 0;
        memset(tempBuf, 0, sizeof(tempBuf));


        snprintf(tempBuf, sizeof(tempBuf), "%s", inet_ntoa(dest.sin_addr));
    }*/
}

string getSource(const u_char* Buffer, size_t Size){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    source.sin_family = AF_INET;

    return inet_ntoa(source.sin_addr);
}

string getDest(const u_char* Buffer, size_t Size){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    dest.sin_family = AF_INET;

    return inet_ntoa(dest.sin_addr);
}

static int parseTLS(const u_char* Buffer, size_t Size){
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    const u_char* temp = Buffer;
    Buffer += HEADER_LEN;
    size_t len;
    size_t pos = TLS_HEADER_LEN;
    string currentIPServer, currentIPClient;
    //list<struct connectionInfo> ci;

    if (Size < TLS_HEADER_LEN){
        return -1;
    }
/*    int count = 0;
    if (userArgs.currentPacketSize > 1500){
        for (int i = 0;i < userArgs.currentPacketSize;i++) {
            if (Buffer[0] == 0x16 && Buffer[1] == 0x03) {
                break;
            } else if (Buffer[0] == 0x17 && Buffer[1] == 0x03) {
               /* ci.ipClient = getSource(temp,Size); 
                ci.ipServer = getDest(temp,Size);
                if ((ci.ipClient == ciPrev.ipServer || ci.ipClient == ciPrev.ipClient) 
                && (ci.ipServer == ciPrev.ipClient || ci.ipServer == ciPrev.ipServer)){
                    ciLast.timestamp = getTimestamp(temp,Size, "last");
                    ciLast.ipServer = ci.ipServer;
                    ciLast.ipClient = ci.ipClient;
                    ciPrev.length += (ntohs(Buffer[3]) + Buffer[4]);
                    Buffer++;
                    ci.countOfPackets += 1;
                }*/
                //break;
           /* } else {
                Buffer += 1;
                count++;
            }
        }*/
        //printf("%d\n", count);
        
   // }
    switch (Buffer[0]){
        case 0x16:
            if (Buffer[1] == 0x03){
                if (Buffer[2] == 0x00 || Buffer[2] == 0x01 || Buffer[2] == 0x02
                    || Buffer[2] == 0x03 || Buffer[2] == 0x04){
                        if (Buffer[5] == 0x01){
                            if (ciPrev.ipServer != getDest(temp, Size) && ciPrev.ipServer != ""){
                                long result = ciLast.sec - ciPrev.sec;
                                long resultusec = ciLast.usec - ciPrev.usec;
                                char bufik[100] = {0};
                                snprintf(bufik, sizeof(bufik), "%ld.%03ld",result, resultusec);
                                string final = ciPrev.timestamp + ciPrev.ipClient + "," + to_string(ciPrev.port) + "," + 
                                        ciPrev.ipServer + "," + ciPrev.hostname + "," + to_string(ciPrev.length) + "," + 
                                        to_string(ci.countOfPackets + 1) + "," + bufik; 
                                printf("%s\n", final.c_str());
                                ci.countOfPackets = 0;
                            }
                            ciPrev.ipClient = getSource(temp,Size);
                            ciPrev.ipServer = getDest(temp,Size);
                            ci.countOfPackets += 1;
                            ciPrev.port = ntohs(tcph->source);
                            ciPrev.length = (ntohs(Buffer[3]) + Buffer[4]);
                            ciPrev.timestamp = getTimestamp(temp, Size, "prev");
                        } else if (Buffer[5] == 0x02) {
                            ci.ipServer = getSource(temp,Size);
                            ci.ipClient = getDest(temp,Size);
                            if (ci.ipClient == ciPrev.ipClient && ci.ipServer == ciPrev.ipServer){
                                ciLast.timestamp = getTimestamp(temp, Size, "last");
                                ci.countOfPackets += 1;
                                ciPrev.length += (ntohs(Buffer[3]) + Buffer[4]);
                            }
                        }
                        for (int i = HEADER_LEN + TLS_HEADER_LEN; i < userArgs.currentPacketSize; i++){
                            if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                                if (temp[i+1] == 0x03){
                                    if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                                        || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                                            ciPrev.length += (ntohs(temp[i+3]) + temp[i+4]);
                                    }
                                }
                            }
                        }
                    } else {
                        //error lebo nepodporovanz protokol
                    }
            } else {
                //tu bude nejakz error
            }
            break;
        case 0x14:
        case 0x15:    
        case 0x17:
            ci.ipClient = getSource(temp,Size); 
            ci.ipServer = getDest(temp,Size);
            if ((ci.ipClient == ciPrev.ipServer || ci.ipClient == ciPrev.ipClient) 
                && (ci.ipServer == ciPrev.ipClient || ci.ipServer == ciPrev.ipServer)){
                ciLast.timestamp = getTimestamp(temp,Size, "last");
                ciLast.ipServer = ci.ipServer;
                ciLast.ipClient = ci.ipClient;
                ciPrev.length += (ntohs(Buffer[3]) + Buffer[4]);
                ci.countOfPackets += 1;
            }
            for (int i = HEADER_LEN + TLS_HEADER_LEN; i < userArgs.currentPacketSize; i++){
                if (temp[i] == 0x14 || temp[i] == 0x15 || temp[i] == 0x16 || temp[i] == 0x17){
                    if (temp[i+1] == 0x03){
                        if (temp[i+2] == 0x00 || temp[i+2] == 0x01 || temp[i+2] == 0x02
                            || temp[i+2] == 0x03 || temp[i+2] == 0x04){
                                ciPrev.length += (ntohs(temp[i+3]) + temp[i+4]);
                        }
                    }
                }
            }
            break;
        default:
            for (int i = 0; i < userArgs.currentPacketSize - (HEADER_LEN + TLS_HEADER_LEN); i++){
                if (Buffer[i] == 0x14 || Buffer[i] == 0x15 || Buffer[i] == 0x16 || Buffer[i] == 0x17){
                    if (Buffer[i+1] == 0x03){
                        if (Buffer[i+2] == 0x00 || Buffer[i+2] == 0x01 || Buffer[i+2] == 0x02
                            || Buffer[i+2] == 0x03 || Buffer[i+2] == 0x04){
                                ciPrev.length += (ntohs(Buffer[i+3]) + Buffer[i+4]);
                        }
                    }
                }
            }
    }       
    // overit handshake
    /*if (Buffer[0] == 0x16){
        if (Buffer[5] == 0x01) {
            serverHandshake = true;
            ci.ipClient = getSource(temp,Size);
            ci.ipServer = getDest(temp, Size);
            ci.countOfPackets += 1;
            if ((ciPrev.ipServer != ci.ipServer) && \
                (ciPrev.ipClient != "" || ciPrev.ipServer != "")) {
                ciPrev.closed = false;
                long result = ciLast.sec - ciPrev.sec;
                long resultusec = ciLast.usec - ciPrev.usec;
                char bufik[100] = {0};
                snprintf(bufik, sizeof(bufik), "%ld.%03ld",result, resultusec);
                string final = ciPrev.timestamp + ciPrev.ipClient + "," + to_string(ciPrev.port) + "," + 
                        ciPrev.ipServer + "," + ciPrev.hostname + "," + to_string(ciPrev.length) + "," + 
                        to_string(ci.countOfPackets - 1) + "," + bufik; 
                printf("%s\n", final.c_str());
                ci.countOfPackets = 1;
            }
            if (!ciPrev.closed){
                ciPrev.ipClient = ci.ipClient;
                ciPrev.ipServer = ci.ipServer;
                ciPrev.port = ntohs(tcph->source);
                ciPrev.length = (ntohs(Buffer[3]) + Buffer[4]);
                //ciPrev.countOfPackets = 1;
                ciPrev.timestamp = getTimestamp(temp, Size, "prev");
                ciPrev.closed = true;
            }
        
        } else if (Buffer[5] == 0x02) {
            serverHandshake = false;
            ci.ipServer = getSource(temp,Size); 
            ci.ipClient = getDest(temp,Size);
            if (ci.ipClient == ciPrev.ipClient && ci.ipServer == ciPrev.ipServer){
                //ci.ipClient = userArgs.ipClient;
                //ci.ipServer = userArgs.ipServer;
                ci.timestamp = getTimestamp(temp, Size, "actual");
                ciPrev.length += (ntohs(Buffer[3]) + Buffer[4]);
                ci.handshakeMade = true;
                ci.countOfPackets += 1;
                return 0;
            } else return 1;
        } else return 1;
    } else if (Buffer[0] == 0x17){
        ci.ipClient = getSource(temp,Size); 
        ci.ipServer = getDest(temp,Size);
        if ((ci.ipClient == ciPrev.ipServer || ci.ipClient == ciPrev.ipClient) 
        && (ci.ipServer == ciPrev.ipClient || ci.ipServer == ciPrev.ipServer)){
            ciLast.timestamp = getTimestamp(temp,Size, "last");
            ciLast.ipServer = ci.ipServer;
            ciLast.ipClient = ci.ipClient;
            ciPrev.length += (ntohs(Buffer[3]) + Buffer[4]);
            ci.countOfPackets += 1;
            return 0;
        }
    } else if (Buffer[0] == 0x14) {
        ci.ipClient = getSource(temp,Size); 
        ci.ipServer = getDest(temp,Size);
        if ((ci.ipClient == ciPrev.ipClient || ci.ipClient == ciPrev.ipServer) 
        && (ci.ipServer == ciPrev.ipClient || ci.ipServer == ciPrev.ipServer)){
            ciLast.timestamp = getTimestamp(temp,Size,"last");
            ciLast.ipServer = ci.ipServer;
            ciLast.ipClient = ci.ipClient;
            ciPrev.length += (ntohs(Buffer[3]) + Buffer[4]);
            ci.countOfPackets += 1;
            return 0;
        }
    } else return -1;
*/

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
    return parse_extension(Buffer + pos, len);

}

static int parse_extension(const uint8_t *Buffer, size_t Size){
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
            return parse_server_name_extension(Buffer + pos + 4, len);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != Size)
        return -5;

    return -2;

}

static int parse_server_name_extension(const uint8_t *Buffer, size_t Size){
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < Size) {
        len = ((size_t)Buffer[pos + 1] << 8) +
            (size_t)Buffer[pos + 2];

        if (pos + 3 + len > Size)
            return -5;

        switch (Buffer[pos]) { /* name type */
            case 0x00: /* host_name */
                //if (allocHostname(len)) return 1;
                /*hostname = malloc(sizeof(char*)*(len + 1));
                if (*hostname == NULL) {
                    printf("malloc() failure");
                    return -4;
                }*/

                ciPrev.hostname = (const char *)(Buffer + pos + 3);

                (ciPrev.hostname)[len] = '\0';
                hostnameFound = true;
                //printf("%s", *hostname);

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
void printTCP(const u_char* Buffer, int Size) {

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    const struct ip6_hdr* ipv6Hdr = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short ip6hdrlen = 5 * 8;   // ipv6hdrlen
    struct tcphdr* tcph6 = (struct tcphdr*)(Buffer + ip6hdrlen + sizeof(struct ethhdr));
   // connectionInfo.port = ntohs(tcph->source);


    //getTimestamp(Buffer, Size);
    parseTLS(Buffer, Size - 54);
    char finalBuf[2048];
    if (ipv6) {
        snprintf(finalBuf, sizeof(finalBuf), "%s %u > %s %u", buf, ntohs(tcph6->source), tempBuf, ntohs(tcph6->dest));
        printf("%s\n\n", finalBuf);
        int hdrlen = ip6hdrlen + 14 + tcph6->doff * 4;
        //dataFlush(Buffer, Size, hdrlen);
    }
    else {
        /*if (!hostnameFound)
            snprintf(finalBuf, sizeof(finalBuf), "%s,%u,%s,%u", buf, ntohs(tcph->source), tempBuf, ntohs(tcph->dest));
        else {
            snprintf(finalBuf, sizeof(finalBuf), "%s,%u,%s,%s,%u", buf, ntohs(tcph->source), tempBuf, userArgs.hostname.c_str(), ntohs(tcph->dest));
            hostnameFound = false;
        }
        printf("%s\n\n", finalBuf);
        int hdrlen = iphdrlen + 14 + tcph->doff * 4;
        //dataFlush(Buffer, Size, hdrlen);*/
    }
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

    /*  - loop through founded interfaces, if interface is matched with user
          defined interface, breaks the loop and continue in code
        - if any interface match with user defined interface, error is raised
        - if user doesn't specify interface, all of system interfaces are written to
          stdout and program ends with EXIT_SUCCESS
    */
    if (userArgs.interfaceSet){
        for (temp = interfaces; temp; temp = temp->next) {
            if (userArgs.interfaceSet) {
                if (strcmp(userArgs.interface.c_str(), temp->name) == 0) {
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

     // for network mask, so we can apply a filter later on
   /* if (pcap_lookupnet(userArgs.interface, &net, &mask, error) == -1) {
        fprintf(stderr, "Netmask wasn't found or enable to reach for device %s\n", userArgs.interface);
        net = 0;
        mask = 0;
    }*/

    // opening specified device for sniffing
    //pcap_t* dev = pcap_open_offline(userArgs.file, error);
    pcap_t* dev = pcap_open_offline("/home/student/Desktop/isa/a1.pcapng", error);
    if (!dev) {
        fprintf(stderr, "Opening of device %s wasn't successful. Error: %s \n", userArgs.interface, error);
        return EXIT_FAILURE;
    }

    // loop with a callback function
    pcap_loop(dev, 0, processPacket, NULL);
    pcap_close(dev);
    long result = ciLast.sec - ciPrev.sec;
    long resultusec = ciLast.usec - ciPrev.usec;
    char bufik[100];
    snprintf(bufik, sizeof(bufik), "%ld.%03ld",result, resultusec);
    string final = ciPrev.timestamp + ciPrev.ipClient + "," + to_string(ciPrev.port) + "," +
                    ciPrev.ipServer + "," + ciPrev.hostname + "," + to_string(ciPrev.length) + "," +
                    to_string(ci.countOfPackets + 1) + "," + bufik; 
    printf("%s\n", final.c_str());

    return EXIT_SUCCESS;
}
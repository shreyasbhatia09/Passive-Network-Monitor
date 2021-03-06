#include "../include/optparser.h"

#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <cstdio>
#include <time.h>
#include <cstring>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0800		/* IP protocol */
#define ETHERTYPE_ARP	0x0806		/* Addr. resolution protocol */
#define isNULL(x) if(x==NULL)
#define TIME_BUFFER 100
using namespace std;

/// PROTOCOL HEADERS START FROM HERE
/// REFERENCE FROM http://www.tcpdump.org/pcap.html

#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet
{
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

/* UDP header */

struct sniff_udp
{
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* udp length */
    u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */
#define SIZE_ICMP        8               /* length of ICMP header */

/// PROTOCOL ENDS HERE

/// HELPER FUNCTIONS ///

/// Function to print the mac address from ether host
void printMACAddress(u_char *ether_host)
{
    u_char *ptr = ether_host;
    for (int i=0; i<ETHER_ADDR_LEN; i++)
        printf("%02X%s",*ptr++, (i==ETHER_ADDR_LEN-1)?"":":");
}

/// REFERENCE FROM http://www.tcpdump.org/sniffex.c
void print_hex_ascii_line( u_char *payload, int len, int offset)
{

    int i;
    int gap;
    u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}


///print packet payload data (avoid printing binary data)
void print_payload(u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; )
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

/// print protocol data if size not zero
void printProtocolData(string protocol, u_char *payload,int protocolsize)
{
    cout<<protocol<<endl;
    // if size is greater than 0
    if(protocolsize)
        print_payload(payload, protocolsize);
}

/// Function to check wether a payload consists of string
/// This function handles the case when strstr encounters EOF
int stringCheck(char *payload, char *str,int sizePayload)
{
    if(str[0]==0)
        return 0;


    char stringcheck[sizePayload];
    strncpy(stringcheck, (char *)payload, sizePayload);
    //To handle non printable characters
    for(int i = 0; i < strlen(stringcheck); i++)
    {
        if(!isprint(stringcheck[i]))
            stringcheck[i]=char(27);
    }
    if (strstr(stringcheck, (char *)str) == NULL)
        return 1;

    return 0;
}

/// Packet Handler
void packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    u_char *payload;
    string protocol;
    int sizePayload;

    struct sniff_ethernet *ethernetHeader = (struct sniff_ethernet *)(packet);
    struct sniff_ip *ipHeader = (struct sniff_ip *) (packet+SIZE_ETHERNET);
    u_int sizeIpHeader = IP_HL(ipHeader)*4;

    // If invalid packet then return
    if(sizeIpHeader < 20)
        return;

    // initilize port values to -1.
    u_short sport=-1;
    u_short dport=-1;

    // Switch case to handle different types of protocols
    switch(ipHeader->ip_p)
    {
        // TCP PROTOCOL
        case IPPROTO_TCP:
        {
            protocol = "TCP";
            struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + sizeIpHeader);
            int sizeTcp = TH_OFF(tcp)*4;
            payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader + sizeTcp);
            sizePayload = ntohs(ipHeader->ip_len) - (sizeTcp+sizeIpHeader);

            if(sizeTcp<20)
            {
                cout<<"Invalid TCP Header"<<endl;
                return;
            }
            sport = tcp->th_sport;
            dport = tcp->th_dport;
            break;
        }
        // UDP PROTOCOL
        case IPPROTO_UDP:
        {
            protocol = "UDP";
            struct sniff_udp *udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + sizeIpHeader);
            payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader + SIZE_UDP);
            sizePayload = ntohs(ipHeader->ip_len) - (SIZE_UDP + sizeIpHeader);
            sport = udp->uh_sport;
            dport = udp->uh_dport;
            break;
        }
        // ICMP PROTOCOL
        case IPPROTO_ICMP:
        {
            protocol = "ICMP";
            payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader + SIZE_ICMP);
            sizePayload = ntohs(ipHeader->ip_len) - (SIZE_ICMP + sizeIpHeader);
            break;
        }
        // OTHER PROTOCOLS
        default:
        {
            protocol = "UNKNOWN";
            payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader );
            sizePayload = ntohs(ipHeader->ip_len) - (sizeIpHeader);
            break;
        }
    }

    // if we have to find a string match inside the payload
    if(args!=NULL)
    {

        char stringcheck[sizePayload];
        strncpy(stringcheck, (char *)payload, sizePayload);
        //To handle non printable characters
        for(int i = 0; i < strlen(stringcheck); i++)
        {
            // replace every non printable character with 'ESC'
            // so that strstr doesnt fail when it encounters EOF
            if(!isprint(stringcheck[i]))
                stringcheck[i]=u_char(27);
        }
        if (strstr(stringcheck, (char *)args) == NULL)
            return;

    }
    // PRINTING BEGINS FROM HERE
    struct tm * time = localtime((const time_t *)&packet_header->ts.tv_sec);
    char timeBuffer[TIME_BUFFER];

    strftime(timeBuffer, TIME_BUFFER, "%F %H:%M:%S", time);
    //Print time
    cout<<timeBuffer<<" ";
    //Print mac address
    printMACAddress(ethernetHeader->ether_shost);
    cout<< " -> ";
    printMACAddress(ethernetHeader->ether_dhost);
    //print ethertype
    printf("type 0x%x",ntohs(ethernetHeader->ether_type));
    //print packet length
    cout<<" "<<"len "<<(packet_header->len)<<" ";
    //handle other type packets
    if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP)
    {
        cout<<"ARP Packet"<<endl;
        return;
    }
    // Print a new line to format the output
    cout<<endl;

    //Print IP address with ports
    cout<<inet_ntoa(ipHeader->ip_src);
    if(sport!=-1) cout<<":"<<ntohs(sport);

    cout<<" " << inet_ntoa(ipHeader->ip_dst);
    if(dport!=-1) cout<<":"<<ntohs(dport)<<" ";

    // if size is non zero print the payload
    if(sizePayload)
        printProtocolData(protocol, payload, sizePayload);
    cout<<endl;

}
/// Convert to human readable time format
string epochToLocalTime(long long int)
{
    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);
}

int main(int argc, char **argv)
{
    char *device,  errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    pcap_t *handle;
    struct pcap_pkthdr header;
    char *string_cmp;
    int c;
    char *fileName = NULL;
    char *interface = NULL;
    char *stringMatch = NULL;
    string expressionString;
    extern char * optarg;
    extern int optind;
    // using getopts to get the arguments
    while ((c = getopt (argc, argv, "r:s:i:")) != -1)
        switch (c)
        {
            case 'r':
                fileName = optarg;
                break;
            case 's':
                stringMatch = (optarg);
                break;
            case 'i':
                interface = (optarg);
                break;
            case '?':
                fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                break;
        }
    // append the the rest of the argument to make the expression string
    for ( ; optind < argc; optind++)
            expressionString+=argv[optind];

    // if interface is NULL
    isNULL(interface)
    {
        // if filename is NULL
        isNULL(fileName)
        {
            cout<<"Taking default interface "<<endl;
            device = pcap_lookupdev(errbuf);
            isNULL(device)
            {
                cout<<"Default Device not found"<<endl;
                return 0;
            }
            else
                cout<<"Found default interface: "<<device<<endl;
                handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
        }
        else
        {
            handle = pcap_open_offline(fileName, errbuf);
        }
    }
    else
    {
        device = interface;
        cout<<"Choosing interface as "<<device<<endl;
        handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    }
    // if handle is null
    isNULL(handle)
    {
        cout<<"Cannot open the device :"<<errbuf<<endl;
        return 0;
    }
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        cout<<device<<" is not an Ethernet\n"<<endl;
        exit(EXIT_FAILURE);
    }
    // if there is an expression defined we need to compile and filter it
    if(expressionString.length()>0)
    {
        pcap_lookupnet(device, &net, &mask, errbuf);
        char * exp = new char[expressionString.length() + 1];
        std::strcpy(exp,expressionString.c_str());
        if (pcap_compile(handle, &fp, exp, 0, net) == -1)
        {
            cout<<"Couldn't parse filter "<<exp<<": "<<pcap_geterr(handle)<<endl;
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1)
        {
            cout<<"Couldn't install filter "<<exp<<" "<<pcap_geterr(handle)<<endl;
            return(2);
        }
    }
    const u_char *packet;

    pcap_loop(handle, -1, packet_handler, (u_char *)stringMatch);

}

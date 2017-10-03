#include "../include/optparser.h"

#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <cstdio>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define isNULL(x) if(x==NULL)
using namespace std;

/// PROTOCOL HEADERS START FROM HERE
/// REFERENCE FROM http://www.tcpdump.org/pcap.html

#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
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

struct sniff_tcp {
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

struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */
#define SIZE_ICMP        8               /* length of ICMP header */

/// PROTOCOL ENDS HERE

/// HELPER FUNCTIONS ///


void printMACAddress(u_char *ether_host)
{
    u_char *ptr = ether_host;
    for (int i=0;i<ETHER_ADDR_LEN;i++)
        printf("%x%s",*ptr++, (i==ETHER_ADDR_LEN-1)?"":":");
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
	for(i = 0; i < len; i++) {
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
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
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
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
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
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void printProtocolData(string protocol, u_char *payload ,int protocolsize)
{
    cout<<protocol<<endl;
    if(protocolsize)
        print_payload(payload, protocolsize);
}


void packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    struct sniff_ethernet *ethernetHeader = (struct sniff_ethernet *)(packet);
    struct sniff_ip *ipHeader = (struct sniff_ip *) (packet+SIZE_ETHERNET);
    u_int sizeIpHeader = IP_HL(ipHeader)*4;
    u_char *payload;
    string protocol;
    int sizePayload;

    if(sizeIpHeader < 20)
    {
        cout<<"Invalid IP Header Length"<<endl;
        return;
    }

    printf("type %x",ntohs(ethernetHeader->ether_type));
    string time = ctime((const time_t *)&packet_header->ts.tv_sec);
    time = time.substr(0,time.size()-1);
    cout<<time<<" ";
    printMACAddress(ethernetHeader->ether_shost);
    cout<< " -> ";
    printMACAddress(ethernetHeader->ether_dhost);
    cout<<" "<<inet_ntoa(ipHeader->ip_src)<< " " << inet_ntoa(ipHeader->ip_dst) <<" ";
    cout<<" "<<"len "<<ntohs(ipHeader->ip_len)<<" ";



    switch(ipHeader->ip_p)
    {
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
			break;
        }
		case IPPROTO_UDP:
        {

			protocol = "UDP";
			payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader + SIZE_UDP);
            sizePayload = ntohs(ipHeader->ip_len) - (SIZE_UDP + sizeIpHeader);
			break;
        }
		case IPPROTO_ICMP:
        {
            protocol = "ICMP";
            payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader + SIZE_ICMP);
            sizePayload = ntohs(ipHeader->ip_len) - (SIZE_ICMP + sizeIpHeader);
            break;
        }

		default:
        {
            protocol = "UNKNOWN";
            payload = (u_char *)(packet + SIZE_ETHERNET + sizeIpHeader );
            sizePayload = ntohs(ipHeader->ip_len) - (sizeIpHeader);
            break;
        }
	}
	if(sizePayload)
            printProtocolData(protocol, payload,sizePayload);
	cout<<endl;
}

string epochToLocalTime(long long int)
{
    time_t rawtime;
  struct tm * timeinfo;

  time (&rawtime);
  timeinfo = localtime (&rawtime);
}

int main(int argc, char **argv)
{
    optparse::OptionParser parser = optparse::OptionParser().description("Options for the application");

    parser.add_option("-i", "--interface").dest("interface")
    .help("Live capture from the network device");
    parser.add_option("-s", "--stringMatch").dest("stringMatch")
    .help("Read packets from <file> in tcpdump format");
    parser.add_option("-r", "--fileName").dest("fileName")
    .help("Keep only packets that contain <string> in their payload");

    const optparse::Values options = parser.parse_args(argc, argv);
    const vector<std::string> args = parser.args();
    char *device,  errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    char *expression=NULL;
    struct pcap_pkthdr header;

    if(argc%2 ==0)
        expression = argv[argc-1];

    if (options["interface"] == "")
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
    }
    else
    {
        device = new char[options["interface"].length() + 1];
        strcpy(device, options["interface"].c_str());
        cout<<"Choosing interface as "<<device<<endl;
    }
    pcap_t *handle;
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    isNULL(handle)
    {
        cout<<"Cannot open the device :"<<errbuf<<endl;
        return 0;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
		cout<<device<<" is not an Ethernet\n"<<endl;
		exit(EXIT_FAILURE);
	}
    if(expression!=NULL)
    {
        pcap_lookupnet(device, &net, &mask, errbuf);
        if (pcap_compile(handle, &fp, expression, 0, net) == -1)
        {
            cout<<"Couldn't parse filter "<<expression<<": "<<pcap_geterr(handle)<<endl;
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cout<<"Couldn't install filter "<<expression<<" "<<pcap_geterr(handle)<<endl;
            return(2);
        }
    }

    const u_char *packet;
    pcap_loop(handle , -1 , packet_handler , NULL);

}

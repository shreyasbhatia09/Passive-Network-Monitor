#include "../include/optparser.h"

#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <cstdio>
#include <string.h>

#define isNULL(x) if(x==NULL)
using namespace std;

void packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    printf("Packet capture length: %d\n", packet_header->caplen);
    printf("Packet total length %d\n", packet_header->len);
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

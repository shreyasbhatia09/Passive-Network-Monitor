#include "../include/optparser.h"

#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <cstdio>
#include <string.h>

#define isNULL(x) if(x==NULL)
using namespace std;

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
    if (options["interface"] == "")
    {
        cout<<"Taking default interface "<<endl;
        device = pcap_lookupdev(errbuf);
        isNULL(device)
            cout<<"Default Device not found"<<endl;
        else
            cout<<"Found default interface: "<<device<<endl;

    }
    else
    {
        device = new char[options["interface"].length() + 1];
        strcpy(device, options["interface"].c_str());
    }

    pcap_t *handle;
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    isNULL(handle)
        cout<<"Cannot open the device :"<<errbuf<<endl;
}

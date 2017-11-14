

Passive Network Monitoring
-------------------------------------------------------------------------------

Overview
----------------------------------------

The folder structure is as follows

Network Monitor
 |_bin
 |_build
 |_docs
 |_include
 |_src

To build the project please use the following command on the root level of the folder.

Command: make all

To remove the output binaries, please use the following command on the root level of the folder

Command make clean

The bin folder consits of the binary generated. 
The build folder contains the the intermediate build outputs. 
The docs folder contains the documentation of the project.
includes folder contains the additional headers to be included.
src contains the source file for this project which is a single file mydump.cpp

After 'make all' command the binary generated goes inside the bin folder. The name of the binary generated is mydump.

The program conforms to the following specification:

mydump [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on. Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format.

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice. 


Implementation
----------------------------

We have used the pcap.h library to build this binary. The binary is built in C++. To get the arguments (-r, -s, -i and expression) 
getopts is used. If the interface and the filename is not defined we pick up the default interface. If an expression is passed in the arguments
we are going to compile and filter the packets using the pcap_compile and pcap_setfilter functions. The packet capture is done indefinitely using  unti pcap_loop function which calls a callback function 'packet_handler'.

The packet_handler function handles each and every packet based upon the IP Protocols (TCP, UDP, ICMP) and their corresponding details are 
shown. First the MAC Address, Time and Ether type and length is printed from the Ethernet frame. For IP packets we are printing the IP address with ports (for TCP and UDP). If the Packet contains a payload, the payload is also printed. The implementation uses various helper functions to print or to handle the packets.

Output from default interface
--------------------------------------

shreyas@shreyas-Ubuntu:~/Desktop/network security/Network Monitor$ sudo bin/mydump 
Taking default interface 
Found default interface: wlp6s0
2017-10-14 20:26:45 64:5A:04:46:AB:45 -> B8:AF:67:63:A3:28type 0x800 len 342 
172.24.18.245:68 130.245.255.4:67 UDP
00000   01 01 06 00 bc 4d db 2f  00 00 00 00 ac 18 12 f5    .....M./........
00016   00 00 00 00 00 00 00 00  00 00 00 00 64 5a 04 46    ............dZ.F
00032   ab 45 00 00 00 00 00 00  00 00 00 00 00 00 00 00    .E..............
00048   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00064   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00080   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00096   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00112   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00128   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00144   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00160   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00176   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00192   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00208   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00224   00 00 00 00 00 00 00 00  00 00 00 00 63 82 53 63    ............c.Sc
00240   35 01 03 0c 0e 73 68 72  65 79 61 73 2d 55 62 75    5....shreyas-Ubu
00256   6e 74 75 37 12 01 1c 02  03 0f 06 77 0c 2c 2f 1a    ntu7.......w.,/.
00272   79 2a 79 f9 21 fc 2a ff  00 00 00 00 00 00 00 00    y*y.!.*.........
00288   00 00 00 00 00 00 00 00  00 00 00 00                ............

2017-10-14 20:26:46 64:5A:04:46:AB:45 -> B8:AF:67:63:A3:28type 0x800 len 108 
172.24.18.245:54426 31.13.71.1:443 TCP
00000   17 03 03 00 25 00 00 00  00 00 00 00 27 1f 65 fb    ....%.......'.e.
00016   3c 71 1b b2 67 1e 55 94  69 6e b7 ac a1 94 b2 29    <q..g.U.in.....)
00032   bc 90 1a 7a e1 39 a6 ae  97 55                      ...z.9...U

2017-10-14 20:26:46 64:5A:04:46:AB:45 -> B8:AF:67:63:A3:28type 0x800 len 66 
172.24.18.245:42688 173.194.204.188:5228 
2017-10-14 20:26:46 64:5A:04:46:AB:45 -> B8:AF:67:63:A3:28type 0x800 len 76 
172.24.18.245:55444 130.245.255.4:53 UDP
00000   5c 01 01 00 00 01 00 00  00 00 00 00 05 6d 74 61    \............mta
00016   6c 6b 06 67 6f 6f 67 6c  65 03 63 6f 6d 00 00 01    lk.google.com...
00032   00 01                                               ..






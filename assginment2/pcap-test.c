#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

/* GO : ethernet header */
#define ETHER_ADDR_LEN 6
struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};
#define ETHER_IP 0x0800
/* GO : ethernet header end */

/* GO : ip header */
struct libnet_ipv4_hdr
{
	u_int8_t ip_hl:4,      /* header length */
	ip_v:4;         /* version */

	u_int8_t ip_tos;       /* type of service */

	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;

	u_int8_t ip_ttl;          /* time to live */
	u_int8_t ip_p;            /* protocol */
	u_int16_t ip_sum;         /* checksum */
	u_int8_t ip_src[4];  /* source address */
	u_int8_t ip_dst[4]; /* dest address */
};
#define TCP 0x06
/* GO : ip header end */

/* GO : tcp header */
struct libnet_tcp_hdr
{
	u_int16_t th_sport;       /* source port */
	u_int16_t th_dport;       /* destination port */
	u_int32_t th_seq;          /* sequence number */
	u_int32_t th_ack;          /* acknowledgement number */
	u_int8_t th_x2:4,         /* (unused) */
	th_off:4;        /* data offset */
	u_int8_t  th_flags;       /* control flags */
	u_int16_t th_win;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
};
/* GO : tcp header end */

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) { //GO : packet get
		struct pcap_pkthdr* header; // GO: header pointer : meta - packet time, packet length
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet); 
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		/* GO : ethernet header */
		struct libnet_ethernet_hdr *ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
        /* GO : ip header*/
		packet += 14;
		struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr*)packet;

		u_int8_t protocol = ipv4_hdr->ip_p;
		if(protocol!=TCP) continue;

		for(int i=0;i<6;i++){
			if(i!=5) {
				printf("%02x:", ethernet_hdr->ether_shost[i]);
				continue;
			}
			printf("%02x -> ",ethernet_hdr->ether_shost[i]);

		}

		for(int i=0;i<6;i++){
			if(i!=5) {
				printf("%02x:",ethernet_hdr->ether_dhost[i]);
				continue;
			}
			printf("%02x, ",ethernet_hdr->ether_dhost[i]);
		}


		u_int16_t ether_type = ntohs(ethernet_hdr->ether_type);


		if(ether_type != ETHER_IP) continue;


		/* GO : ethernet header end */



		u_char ip_header_length = (ipv4_hdr->ip_hl)<<2;



		/* GO : ip header end*/

		/* GO : tcp header */
		packet += ip_header_length;
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)packet;
		u_int16_t src_port = ntohs(tcp_hdr->th_sport);
		u_int16_t dst_port = ntohs(tcp_hdr->th_dport);

		for(int i=0;i<4;i++) {
			if(i!=3){
				printf("%d.",ipv4_hdr->ip_src[i]);
				continue;
			}
			printf("%d:%d -> ",ipv4_hdr->ip_src[i],src_port);
		}


		for(int i=0;i<4;i++) {
			if(i!=3) {
				printf("%d.",ipv4_hdr->ip_dst[i]);
				continue;
			}
			printf("%d:%d, ",ipv4_hdr->ip_dst[i],dst_port);
		}

		u_int16_t tcp_length = 4*(tcp_hdr->th_off);

		/* GO : http header end */

		/* GO : data */
		packet += tcp_length;
		//printf("ipv4_hdr->ip_len : %u\n", ntohs(ipv4_hdr->ip_len));
		u_int16_t data_length = ntohs(ipv4_hdr->ip_len) - ip_header_length - tcp_length;
		//printf("data_length: %d\n",data_length);

		if(data_length==0) {
			printf("-\n");
		}else{
			for(int i=0;i<20;i++){
				if(data_length-1==i){
					printf("%02x",*packet);
					break;
				}
				else if(i==19) printf("%0x",*packet);
				else printf("%02x|",*packet);
				packet+=1;
			}
			printf("\n");
		}

		printf("============================\n");

		/* GO : data end */


	}

	pcap_close(pcap);
}

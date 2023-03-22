#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>


typedef struct {
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    uint16_t ether_type;
}Ether;
typedef struct {
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}IP;
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
}TCP;
typedef struct {
    Ether eth;
    IP ip;
    TCP tcp;
}Packet;



void print_MAC(uint8_t *addr){
        for(int i=0; i<6; i++){
		printf("%02X",addr[i]);
		if(i==5) break;
		printf(":");
	}
}
void print_eth(Packet *pkt){
	printf("Dst MAC address : ");
        print_MAC(pkt->eth.dst_MAC);
        printf("\nSrc MAC address : ");
        print_MAC(pkt->eth.src_MAC);
	printf("\n");

}
void print_IP(uint32_t ip){
        printf("%d.%d.%d.%d", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}

void print_iph(Packet *pkt){
        printf("Dst IP : ");
        print_IP(pkt->ip.dst_ip);
        printf("\nSrc IP : ");
        print_IP(pkt->ip.src_ip);
	printf("\n");
}

void print_tcph(Packet *pkt){
        printf("Dst port : %d\n", ntohs(pkt->tcp.dst_port));
        printf("Src port : %d\n", ntohs(pkt->tcp.src_port));
}

void print_data(Packet *pkt){
	unsigned char *data;
        data = (unsigned char *)(pkt + sizeof(Ether) + (pkt->ip.v_l & 0xF)*4 + (pkt->tcp.offset_reserved >> 4)*4);
	if(ntohs(pkt->ip.total_len) - (pkt->ip.v_l & 0xF)*4 - (pkt->tcp.offset_reserved >> 4)*4 >=0){;
        	printf("data value\n");
        	for(int i=0; i<10; i++) printf("%02X ", data[i]);
	}
	printf("\n");
}

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

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		Packet *pkt = (Packet *)packet;
		print_eth(pkt);
    		print_iph(pkt);
		print_tcph(pkt);
		print_data(pkt);			

	}

	pcap_close(pcap);
}


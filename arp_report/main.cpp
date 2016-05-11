#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <thread>

void print_bytes(u_int8_t *bytes, int size) {
    for(int i=1; i<=size; i++) {
        printf("%02x ", bytes[i-1]);
        if(i!=1 && i%16==0) {
            printf("\n");
        } else if(i!=1 && i%8==0) {
            printf(" ");
        }
    }
    printf("\n");
}

struct eth_hdr {
    u_int8_t eth_dmac[6];   // ether destination mac주소
    u_int8_t eth_smac[6];  // ether source mac주소
    u_int16_t eth_type;   // ether type
};

struct arp_req {
    u_int16_t arp_hwtype;   // ARP 패킷의 하드웨어 타입
    u_int16_t arp_protype;  // ARP 패킷의 프로토콜 타입
    u_int8_t arp_hlen;   // ARP 패킷의 하드웨어 길이
    u_int8_t arp_plen;   // ARP 패킷의 프로토콜 길이
    u_int16_t arp_opr;   // ARP 패킷의 오퍼레이션
    u_int8_t arp_shwaddr[6];  // ARP 패킷의 소스MAC주소
    u_int8_t arp_sipaddr[4]; // ARP 패킷의 소스IP주소
    u_int8_t arp_thwaddr[6];   // ARP 패킷의 타겟MAC주소
    u_int8_t arp_tproaddr[4]; // ARP 패킷의 타겟IP주소
};

struct eth_arp_req {
    eth_hdr eth;
    arp_req arp;
};

int main()
{
    pcap_t *handle;
    char *dev = "eth1";
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    eth_hdr eth;
    u_char eth_dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth.eth_dmac, eth_dmac, sizeof(eth_dmac));
    u_char eth_smac[6] = {0x18, 0x67, 0xb0, 0xd0, 0xfa, 0xc5};
    memcpy(eth.eth_smac, eth_smac, sizeof(eth_smac));
    eth.eth_type = htons(ETH_P_ARP);
    arp_req arp;
    arp.arp_hwtype = htons(ARPHRD_ETHER);
    arp.arp_protype = htons(ETH_P_IP);
    arp.arp_hlen = sizeof(eth.eth_dmac);
    arp.arp_plen = sizeof(arp.arp_sipaddr);
    arp.arp_opr = htons(ARPOP_REQUEST);
    u_int8_t arp_shwaddr[6] = {0x18, 0x67, 0xb0, 0xd0, 0xfa, 0xc5};
    memcpy(arp.arp_shwaddr, arp_shwaddr, sizeof(arp_shwaddr));
    u_int8_t arp_sproaddr[4] = {0x0a, 0x64, 0x7c, 0xf3};
    memcpy(arp.arp_sipaddr, arp_sproaddr, sizeof(arp_sproaddr));
    u_int8_t arp_thwaddr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(arp.arp_thwaddr, arp_thwaddr, sizeof(arp_thwaddr));
    u_int8_t arp_tproaddr[4] = {0x0a, 0x64, 0x7c, 0x01};
    memcpy(arp.arp_tproaddr, arp_tproaddr, sizeof(arp_tproaddr));

    eth_arp_req req;
    req.eth = eth;
    req.arp = arp;

    print_bytes((u_int8_t*) &req, sizeof(req));

    for (int i=0; i<6; i++) {
    if (pcap_sendpacket(handle,(const u_char*)&req ,(sizeof(req))) != 0)
    {
        printf("arp error\n");
    }
    else
    {
        printf("arp send\n");
    }
    }

    pcap_close(handle);


    return(0);

}

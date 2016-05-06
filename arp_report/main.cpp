/*
1. ARP Request packet를 보내기.
버퍼를 할당하여(Ethernet Header 크기와 ARP Header 크기의 합만큼)
올바른 값을 집어 넣어(Gateway의 mac은 무엇이냐?)라고 물어 보는
 ARP Request 패킷(frame)을 작성하여 패킷을 네트워크에 송신.
이 패킷에 대해서 Gateway가 ARP Reply를 하게 되면 성공.
*/
#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
struct arp_req {
    u_int arp_hwtype[2];   // ARP 패킷의 하드웨어 타입
    u_int arp_protype[2];  // ARP 패킷의 프로토콜 타입
    u_int arp_hlen[1];   // ARP 패킷의 하드웨어 길이
    u_int arp_plen[1];   // ARP 패킷의 프로토콜 길이
    u_int arp_opr[2];   // ARP 패킷의 오퍼레이션
    u_int arp_shwaddr[6];  // ARP 패킷의 소스MAC주소
    u_int arp_sipaddr[4]; // ARP 패킷의 소스IP주소
    u_int arp_thwaddr[6];   // ARP 패킷의 타겟MAC주소
    u_int arp_tipaddr[4]; // ARP 패킷의 타겟IP주소
};
struct eth_hdr {
    u_int eth_dmac[6];   // ether destination mac주소
    u_int eth_smac[6];  // ether source mac주소
    u_int eth_type[2];   // ether type
};
struct eth_arp_req {
    eth_hdr eth;
    arp_req arp;
};
int main()
{
    pcap_t *handle;
    char *dev = "wlan0";
    //u_char packetdata[50]; //총 14+28=42
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    eth_hdr eth;
    u_int eth_dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth.eth_dmac, eth_dmac, sizeof(eth_dmac));
    u_int eth_smac[6] = {0x24, 0xf5, 0xaa, 0x75, 0xa4, 0xdf};
    memcpy(eth.eth_smac, eth_smac, sizeof(eth_smac));
    u_int eth_type[2] = {0x08, 0x06};
    memcpy(eth.eth_type, eth_type, sizeof(eth_type));
    arp_req arp;
    u_int arp_hwtype[2] = {0x00, 0x01};
    memcpy(arp.arp_hwtype, arp_hwtype, sizeof(arp_hwtype));
    u_int arp_protype[2] = {0x08, 0x00};
    memcpy(arp.arp_protype, arp_protype, sizeof(arp_protype));
    u_int arp_hlen[1] = {0x06};
    memcpy(arp.arp_hlen, arp_hlen, sizeof(arp_hlen));
    u_int arp_plen[1] = {0x04};
    memcpy(arp.arp_plen, arp_plen, sizeof(arp_plen));
    u_int arp_opr[2] = {0x00, 0x01};
    memcpy(arp.arp_opr, arp_opr, sizeof(arp_opr));
    u_int arp_shwaddr[6] = {0x24, 0xf5, 0xaa, 0x75, 0xa4, 0xdf};
    memcpy(arp.arp_shwaddr, arp_shwaddr, sizeof(arp_shwaddr));
    u_int arp_sproaddr[4] = {0xc0, 0xa8, 0x00, 0x07};
    memcpy(arp.arp_sipaddr, arp_sproaddr, sizeof(arp_sproaddr));
    u_int arp_thwaddr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(arp.arp_thwaddr, arp_thwaddr, sizeof(arp_thwaddr));
    u_int arp_tproaddr[4] = {0xc0, 0xa8, 0x00, 0x01};
    memcpy(arp.arp_tipaddr, arp_tproaddr, sizeof(arp_tproaddr));

    eth_arp_req *req;
    req->eth = eth;
    req->arp = arp;

    if (pcap_sendpacket(handle,(const u_char*)&req ,(sizeof(req)) != 0)) {
        printf("arp error\n");
    }
    else
    {
     printf("arp send\n");
    }

    pcap_close(handle);
    return(0);
}

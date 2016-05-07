#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

//unsigned char	mymac[] = {0x24, 0xf5, 0xaa, 0x75, 0xa4, 0xdf};
//unsigned char	myip[] = {0xc0, 0xa8, 0x00, 0x07};

int main()
{
    pcap_t *handle;
    char *dev = "wlan0";
    u_char req_packet[42];
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* ethernet destination */
    for(i=0; i<6; i++){
         req_packet[i]=255;
    }
    /* ethernet source */
    req_packet[6]=0x24;
    req_packet[7]=0xf5;
    req_packet[8]=0xaa;
    req_packet[9]=0x75;
    req_packet[10]=0xa4;
    req_packet[11]=0xdf;
    /* ether type */
    req_packet[12]=0x08;
    req_packet[13]=0x06;
    /* arp hardware type */
    req_packet[14]=0x00;
    req_packet[15]=0x01;
    /* arp protocol type */
    req_packet[16]=0x08;
    req_packet[17]=0x00;
    /* arp hardware size */
    req_packet[18]=0x06;
    /* arp protocol size */
    req_packet[19]=0x04;
    /* arp opcode */
    req_packet[20]=0x00;
    req_packet[21]=0x01;
    /* arp my mac */
    req_packet[22]=0x24;
    req_packet[23]=0xf5;
    req_packet[24]=0xaa;
    req_packet[25]=0x75;
    req_packet[26]=0xa4;
    req_packet[27]=0xdf;
    /* arp my ip  */
    req_packet[28]=192;
    req_packet[29]=168;
    req_packet[30]=200;
    req_packet[31]=123;
    /* arp gateway mac */
    for(i=32; i<38; i++) {
        req_packet[i]=0;
    }
    /* arp gateway ip */
    req_packet[38]=192;
    req_packet[39]=168;
    req_packet[40]=200;
    req_packet[41]=1;

    for(i=0; i<6; i++){
        if ((pcap_sendpacket(handle,req_packet,42)) != 0)
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
/*
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
    char *dev = "wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    eth_hdr eth;
    u_char eth_dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth.eth_dmac, eth_dmac, sizeof(eth_dmac));
    u_char eth_smac[6] = {0x24, 0xf5, 0xaa, 0x75, 0xa4, 0xdf};
    memcpy(eth.eth_smac, eth_smac, sizeof(eth_smac));
    eth.eth_type = htons(ETH_P_ARP);
    arp_req arp;
    arp.arp_hwtype = htons(ARPHRD_ETHER);
    arp.arp_protype = htons(ETH_P_IP);
    arp.arp_hlen = 6;
    arp.arp_plen = 4;
    arp.arp_opr = htons(ARPOP_REQUEST);
    u_int8_t arp_shwaddr[6] = {0x24, 0xf5, 0xaa, 0x75, 0xa4, 0xdf};
    memcpy(arp.arp_shwaddr, arp_shwaddr, sizeof(arp_shwaddr));
    u_int8_t arp_sproaddr[4] = {0xc0, 0xa8, 0x00, 0x07};
    memcpy(arp.arp_sipaddr, arp_sproaddr, sizeof(arp_sproaddr));
    u_int8_t arp_thwaddr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(arp.arp_thwaddr, arp_thwaddr, sizeof(arp_thwaddr));
    u_int8_t arp_tproaddr[4] = {0xc0, 0xa8, 0x00, 0x01};
    memcpy(arp.arp_tproaddr, arp_tproaddr, sizeof(arp_tproaddr));
    eth_arp_req req;
    req.eth = eth;
    req.arp = arp;
    if (pcap_sendpacket(handle,(const u_char*)&req ,(sizeof(req)) != 0))
    {
        printf("arp error\n");
    }
    else
    {
        printf("arp send\n");
    }
    pcap_close(handle);
    return(0);
}
*/

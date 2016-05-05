#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

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
    pcap_close(handle);
    return(0);
}

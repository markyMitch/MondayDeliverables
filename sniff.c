#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "myheader.h"

#define  BUFSIZE 1500

void process_ip(struct ipheader* ip);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf("got a sniff packet\n");
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) 
      process_ip((struct ipheader*)(packet + SIZE_ETHERNET));
};
 
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  //char filter_exp[] = "port 23";
  // Don't sniff the packet from/to the specified ether address
  //char filter_exp[] = "not (ether host 08:00:27:c5:79:5f)";
  char filter_exp[] = "";
  bpf_u_int32 net; 

  //Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);	  

  //Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net); 

  pcap_setfilter(handle, &fp); //Setup BPF code on the socket
  pcap_loop(handle, -1, got_packet, NULL); //Capture packets
  pcap_close(handle);   //Close the handle 
  return 0;
}

void process_ip(struct ipheader* ip)
{
    int ip_header_len = ip->iph_ihl * 4;

    printf("-------------------------------------\n");
    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));

    u_char *header = ((u_char *) ip) + ip_header_len;

    /* determine protocol */
    switch(ip->iph_protocol) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
}



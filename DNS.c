#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "myheader.h"


#define BUFSIZE 1500;

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  //char filter_exp[] = "port 23";
  // Don't sniff the packet from/to the specified ether address
  //char filter_exp[] = "not (ether host 08:00:27:c5:79:5f)";
  char filter_exp[] = "dst port 53";
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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) 
      process_ip((struct ipheader*)(packet + SIZE_ETHERNET));
};


/*Need to dynamically access eth# of attacking machine*/
string get_eth()
{

}

unsigned short construct_dns_reply(char *buffer)
{
	struct dnsheader *dns = (struct dnsheader *) buffer;

	//construct the DNS header:
	dns->flags=htons(0x8400); //Flag = response; this is a DNS response

	//the number for certain fields
	dns->QDCOUNT=htons(1); // 1 question field
	dns->ANCOUNT=htons(1); // 1 answer field
	dns->NSCOUNT=htons(1); // 1 name server(authority) field
	dns->ARCOUNT=htons(1); // 1 additional fields

	char *p = buffer + 12; // move the pointer to the beginning of DNS data

	
}
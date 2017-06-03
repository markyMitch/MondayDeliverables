#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>


#include "myheader.h"

/******************************************************************************* 
  Given an IP packet, send it out using raw socket. 
*******************************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Create a raw network socket, and set its options.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
  
    // Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Send the packet out.
    printf("Sending spoofed IP packet...\n");
    int returnval = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    printf("return is %i bytes\n",returnval);
    close(sock);
}


/*****************************************************
   Size should be number of bytes. This implementation
   assumes that size is even, so no padding is needed. 
   This one should be retired as well.
*****************************************************/
unsigned short csum(unsigned short *buf, int size) {
	unsigned long sum;
        int nwords = size/2;

	for(sum=0; nwords>0; nwords--)
		sum += *buf++;

	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}



unsigned short in_cksum(unsigned short *buf,int length)
{
        unsigned short *w = buf;
        int nleft = length;
        int sum = 0;
        unsigned short temp=0;

        /*
        * The algorithm uses a 32 bit accumulator (sum), adds
        * sequential 16 bit words to it, and at the end, folds back all the
        * carry bits from the top 16 bits into the lower 16 bits.
        */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* treat the odd byte at the end, if any */
        if (nleft == 1) {
                *(u_char *)(&temp) = *(u_char *)w ;
                sum += temp;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     // add hi 16 to low 16 
        sum += (sum >> 16);                     // add carry 
	return (unsigned short)(~sum);
}


#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>

#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                const u_char *packet);
void spoof_icmp_reply(struct ipheader* ip);
void send_raw_ip_packet(struct ipheader* ip);
 
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  //char filter_exp[] = "port 23";
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

/*********************************************************************** 
  This function will be invoked by pcap, whenever a packet is captured.
************************************************************************/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (eth->ether_type != ntohs(0x0800))  return; // not an IP packet

    struct ipheader* ip = (struct ipheader*)(packet + SIZE_ETHERNET);
    int ip_header_len = ip->iph_ihl * 4;

    printf("-------------------------------------\n");
    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));

    /* determine protocol */
    if (ip->iph_protocol ==  IPPROTO_ICMP){
         printf("   Protocol: ICMP\n");
         spoof_icmp_reply(ip);
    }
}

/*********************************************************************** 
  Given a captured ICMP echo request packet, construct a spoofed ICMP 
  echo reply, which includes IP + ICMP (there is no data).
************************************************************************/
void spoof_icmp_reply(struct ipheader* ip)
{
    int ip_header_len = ip->iph_ihl * 4;
    const char buffer[1500];

    struct icmpheader* icmp = (struct icmpheader *) ((u_char *)ip + 
                                                     ip_header_len);
    if(icmp->icmp_type!=8) { // only process ICMP echo request
        printf("Not an echo Request\n");
        return;
    }

    // make a copy from original packet to buffer(faked packet)
    memset((char*)buffer, 0, 1500);
    memcpy((char*)buffer, ip, ntohs(ip->iph_len));
    struct ipheader   * newip    = (struct ipheader *) buffer;
    struct icmpheader * newicmp = (struct icmpheader *) 
                                  ((u_char *)buffer + ip_header_len);

    // Construct IP: swap src and dest in faked ICMP packet
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 20;
    newip->iph_protocol = IPPROTO_ICMP; 

    //Fill in all the needed ICMP header information.
    //ICMP Type: 8 is request, 0 is reply.
    newicmp->icmp_type = 0;

    //Calculate the checksum for integrity. ICMP checksum includes the data 
    newicmp->icmp_chksum = 0; // Set it to zero first
    newicmp->icmp_chksum = in_cksum((unsigned short *)newicmp, 
                                         ntohs(ip->iph_len) - ip_header_len);

    send_raw_ip_packet(newip);
}


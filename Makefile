all: sniff icmp_spoof icmp_snoof DNS 


sniff: sniff.c myheader.h
	gcc -o sniff sniff.c -lpcap

icmp_spoof: icmp_spoof.c spoof.c myheader.h
	gcc -o icmp_spoof icmp_spoof.c spoof.c

icmp_snoof: icmp_snoof.c spoof.c myheader.h
	gcc -o icmp_snoof icmp_snoof.c spoof.c -lpcap

DNS: DNS.c myheader.h
	gcc -o DNS DNS.c


clean:	
	rm -f sniff icmp_spoof icmp_snoof 

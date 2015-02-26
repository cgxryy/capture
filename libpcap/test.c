#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
int main()
{
	printf("struct ether_header: %d\n", sizeof(struct ether_header));
	printf("struct iphdr: %d\n", sizeof(struct iphdr));
	printf("struct tcphdr: %d\n", sizeof(struct tcphdr));
	printf("struct udphdr: %d\n", sizeof(struct udphdr));
	printf("struct icmphdr: %d\n", sizeof(struct icmphdr));

	

	return 0;
}

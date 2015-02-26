// =====================================================================================
// 
//       Filename:  parse_protocol.cpp
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月26日 10时47分59秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#include "parse_protocol.h"

#include <iostream>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iomanip>

using namespace::std;

void Protocol_parse::parse(const struct pcap_pkthdr* pack, const u_char* content)
{
	cout << "==============================================" << endl;
	cout << "The packet's length: " << pack->len << endl;
	cout << "The time of receipt: " << ctime(static_cast<const time_t*>(&(pack->ts.tv_sec))) << endl;
	cout << "Frame:" << endl;
	
	parse_ether(pack, content);
}

void Protocol_parse::parse_ether(const struct pcap_pkthdr* pack, const u_char* content)
{
	struct ether_header* ethernet = reinterpret_cast<struct ether_header*>(const_cast<u_char*>(content));

	const u_char* raw_content = content;
	for ( int i = 0; i < pack->len; i++)
	{
		cout << hex << setw(2) << (int)raw_content[i];
		//格式处理始终不对，C解决
		//printf("%02x", raw_content[i]);
		if ((i+1)%16 == 0)
		      cout << endl;
		else
		      cout << ((i+1)!= pack->len ? ":" : "");
	}
	cout << endl;

	cout << "\nEthernet:"<< endl;
	//目的MAC
	u_char *p = ethernet->ether_dhost;
	int mac_len = ETHER_ADDR_LEN;
	cout << "Dest MAC: ";
	while (mac_len-- > 0)
	{
		cout << setw(3) << hex << (int)*p++ << (mac_len != 0 ? ":" : "");
	}
	cout << endl;

	//源MAC
	p = ethernet->ether_shost;
	mac_len = ETHER_ADDR_LEN;
	cout << "Source MAC: ";
	while (mac_len-- > 0)
	{
		cout << setw(3) << hex << (int)*p++ << (mac_len != 0 ? ":" : "");
	}
	cout << endl;

	parse_network(pack, content + sizeof(struct ether_header), ethernet);
}

void Protocol_parse::parse_network(const struct pcap_pkthdr* pack, const u_char* content, const struct ether_header* ethernet)
{
	switch (ntohs(ethernet->ether_type))
	{
		case ETHERTYPE_IP:
		{
			struct iphdr* ipv4;
			ipv4 = (struct iphdr*)const_cast<u_char*>(content);
			cout << "\nIPV4:"<< endl;
			cout << "IPV4 version: " << ipv4->version << endl;
			cout << "TTL: " << dec << (int)ipv4->ttl << endl;
			cout << "Source IP address: " << inet_ntoa(*(struct in_addr*)&(ipv4->saddr)) << endl;
			cout << "Destination IP address: " << inet_ntoa(*(struct in_addr*)&(ipv4->daddr)) << endl;
			cout << "Protocol: " << (int)ipv4->protocol << endl;
			parse_transport(pack, content + sizeof(struct iphdr), ipv4);
			break;
		}
		case ETHERTYPE_ARP:
		{	
			const u_char* raw_data = content+2; //跳过硬件字段
			cout << "\nARP:" << endl;
			if (*raw_data == 0x08) 	//ARP协议中协议字段，不是以太网中12字节源/目的MAC后的协议字段
			{
				cout << "Source ip: " << static_cast<int>(raw_data[12]) <<
					static_cast<int>(raw_data[13])	<< 
					static_cast<int>(raw_data[14])	<< 
					static_cast<int>(raw_data[15])  << endl;
				cout << "Dest ip: " << static_cast<int>(raw_data[22]) <<
					static_cast<int>(raw_data[23])	<< 
					static_cast<int>(raw_data[24])	<< 
					static_cast<int>(raw_data[25])  << endl;
			}
			break;
		}
		default:
		{
			cout << "This is a unknown packet..."<< endl;
			break;
		}
	}
}

void Protocol_parse::parse_transport(const struct pcap_pkthdr* pack, const u_char* content, const struct iphdr* ip)
{
	switch(ip->protocol)
	{
		//TCP
		case 6:
		{
			struct tcphdr* tcp;
			tcp = reinterpret_cast<struct tcphdr*>(const_cast<u_char*>(content));
			cout << "\nTCP:"<< endl;
			cout << "Source Port: " << dec << (int)ntohs(tcp->source) << endl;
			cout << "Destination Port: " << dec<< (int)ntohs(tcp->dest) << endl;
			cout << "Window size: " << dec << (int)ntohs(tcp->window) << endl;
			cout << "ack: " << dec << (int)ntohs(tcp->ack) << endl;
			cout << "fin: " << dec << (int)ntohs(tcp->fin) << endl;
			cout << "syn: " << dec << (int)ntohs(tcp->syn) << endl;
			cout << "Urgent: " << dec << (int)ntohs(tcp->urg) << endl;
			cout << "Sequence Number: " << dec << (long)ntohl(tcp->seq) << endl;
			cout << "ACK Sequence Number: " << dec << (long)ntohl(tcp->ack_seq) << endl;
			break;
		}
		//UDP
		case 17:
		{
			struct udphdr* udp;
			udp = reinterpret_cast<struct udphdr*>(const_cast<u_char*>(content));
			cout << "\nUDP:"<< endl;
			cout << "Source Port: " << dec << ntohs(udp->source) << endl;
			cout << "Destiantion Port: "<< dec << ntohs(udp->dest) << endl;
			cout << "Len: " << dec << ntohs(udp->len)<< endl;
			break;
		}
		//ICMP
		case 1:
		{
			struct icmphdr* icmp;
			icmp = reinterpret_cast<struct icmphdr*>(const_cast<u_char*>(content));
			cout << "\nICMP:" << endl;
			cout << "Type: " << dec << icmp->type << endl;
			switch(icmp->type)
			{
				case 8:
				{
					cout << "ICMP Echo Request Protocol." << endl;
					break;
				}
				case 0:
				{	
					cout << "ICMP Echo Reply Protocol." << endl;
					break;
				}
			}
			break;
		}
		default:
		{
			cout << "Unknown packet, maybe IGMP..."<< endl;
			break;
		}
	}
}

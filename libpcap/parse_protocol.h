// =====================================================================================
// 
//       Filename:  capture.h
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月24日 23时00分35秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#ifndef PROTOCOL_PARSE_H_
#define PROTOCOL_PARSE_H_

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

class Protocol_parse
{
public:
	Protocol_parse(){}
	~Protocol_parse(){}
	void parse(const struct pcap_pkthdr* pack, const u_char* content);

private:
	//解析数据链路层:以太网,ARP,RARP之类
	void parse_ether(const struct pcap_pkthdr* pack, const u_char* content);
	//解析网络层:IP,ICMP之类  		
	void parse_network(const struct pcap_pkthdr* pack, const u_char* content, const struct ether_header* ethernet);    	
	//解析传输层:TCP,UDP之类
	void parse_transport(const struct pcap_pkthdr* pack, const u_char* content, const struct iphdr* ip); 	
	/*
	 * 自己的思路是，传过来包的char*类型，通过判断类型打印相应包信息后，调用下一层函数，char* 类型相应偏移多少，和json类似 
	 * 最后一层打印数据内容
	 */
};

#endif

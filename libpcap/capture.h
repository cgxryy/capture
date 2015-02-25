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

#ifndef CAPTURE_H_
#define CAPTURE_H_

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

class Protocol_analysis
{
public:
	Protocol_analysis(){}
	~Protocol_analysis(){}
	parse();

private:
	//参数未定
	parse_ether(); 		//解析数据链路层:以太网,ARP,RARP之类
	parse_network();     	//解析网络层:IP,ICMP之类 
	parse_transport(); 	//解析传输层:TCP,UDP之类
	/*
	 * 自己的思路是，传过来包的char*类型，通过判断类型打印相应包信息后，调用下一层函数，char* 类型相应偏移多少，和json类似 
	 * 最后一层打印数据内容
	 */
};


#endif

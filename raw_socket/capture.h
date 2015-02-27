// =====================================================================================
// 
//       Filename:  capture.h
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月27日 17时59分39秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#ifndef CAPTURE_RAW_H_
#define CAPTURE_RAW_H_

#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define RECV_BUF_SIZE 4096

typedef enum{false, true} bool;

//用法
void usage();

//初始化套接字
int socket_init(char* net_name, unsigned short protocol_type, bool promise);

//销毁套接字
void socket_destory(int connfd, char* net_name);

//捕获一次数据包
void capture_once(int connfd, void (*call_back_func)(const u_char*, int));

//捕获数据包
void capture(int connfd, void (*call_back_func)(const u_char*, int));

//协议解析函数
void parse_protocol(const u_char* proto_buf, int length);

#endif

// =====================================================================================
// 
//       Filename:  capture.c
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月27日 18时23分06秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#include "capture.h"

static bool set_network_promise(int connfd, char* net_name, bool choose)
{
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));

	assert(net_name != NULL);
	strcpy(ifr.ifr_name, net_name);

	if (ioctl(connfd, SIOCGIFFLAGS, &ifr) < 0)
	{
		perror("set_network_promise:");
		return false;
	}

	if (choose)
		ifr.ifr_flags |= IFF_PROMISC;
	else 
		ifr.ifr_flags &= ~IFF_PROMISC;
	
	if (ioctl(connfd, SIOCSIFFLAGS, &ifr) < 0)
	{
		perror("set_network_promise:");
		return false;
	}

	return true;
}

int socket_init(char* net_name, unsigned short protocol_type, bool promise)
{
	int fd;

	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(protocol_type))) < 0)
	{
		perror("socket_init:");
		return -1;
	}

	if (promise)
	{
		if (!set_network_promise(fd, net_name, true))
		{
			close(fd);
			return -1;
		}
	}

	int recv_size = RECV_BUF_SIZE;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_size, sizeof(int)) < 0)
	{
		perror("socket init:");
		close(fd);
		return -1;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, net_name);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("socket init:");
		close(fd);
		return -1;
	}

	struct sockaddr_ll sock_ll;

	bzero(&sock_ll, sizeof(sock_ll));
	sock_ll.sll_family = AF_PACKET;
	sock_ll.sll_ifindex = ifr.ifr_ifindex;
	sock_ll.sll_protocol = htons(protocol_type);

	if (bind(fd, (struct sockaddr*)&sock_ll, sizeof(sock_ll)) < 0)
	{
		perror("bind");
		close(fd);
		return -1;
	}

	return fd;
}

void socket_destory(int connfd, char* net_name)
{
	set_network_promise(connfd, net_name, false);
	close(connfd);
}

void capture_once(int connfd, void (*call_back_func)(const u_char*, int))
{
	u_char recv_buf[RECV_BUF_SIZE];
	socklen_t socklen;
	int size;

	bzero(recv_buf, RECV_BUF_SIZE);
	size = recvfrom(connfd, recv_buf, RECV_BUF_SIZE, 0, NULL, &socklen);
	call_back_func(recv_buf, size);
}

void capture(int connfd, void (*call_back_func)(const u_char*, int))
{
	u_char recv_buf[RECV_BUF_SIZE];
	socklen_t socklen;
	int size;

	while (true)
	{
		bzero(recv_buf, RECV_BUF_SIZE);
		if ((size = recvfrom(connfd, recv_buf, RECV_BUF_SIZE, 0, NULL, &socklen)) < 0)
		{
			continue;
		}
		call_back_func(recv_buf, size);
	}
}

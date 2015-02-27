// =====================================================================================
// 
//       Filename:  1.c
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月27日 17时44分40秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#include "capture.h"

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		usage();
		return 0;
	}

	int fd;
	if ((fd = socket_init(argv[1], ETH_P_IP, false)) < 0)
	{
		return 1;
	}

	int i;
	int n = atoi(argv[2]);
	for ( i = 0; i < n; i++)
	{
		printf("No.%d\t", i+1);
		capture_once(fd, parse_protocol);
	}

	socket_destory(fd, argv[1]);

	return 0;
}


// =====================================================================================
// 
//       Filename:  capture.cpp
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月25日 16时18分40秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#include <iostream>
#include <pcap.h>
#include <cstring>
#include <stdlib.h>
#include "capture.h"

using namespace::std;

int main(int argc, char *argv[])
{	
	Capture init;
	if (argc <= 1)
	{
		init.uiShowUsageOnly = true;
		init.search_print();
		return 0;
	}
	else if (argc == 2)
	{
		init.g_uiDeviceIndex = atoi(argv[1]);
	}
	else 
	{
		init.g_uiDeviceIndex = atoi(argv[1]);
		init.g_acFilter = argv[2];
		cout << "Set Filter: " << init.g_acFilter << endl; 
	}

	init.start();

	return 0;
}



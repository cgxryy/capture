// =====================================================================================
// 
//       Filename:  init_capture.cpp
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月25日 22时23分40秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#include "capture.h"
#include <iostream>
#include "parse_protocol.h"

using namespace::std;

void traffic_callback(unsigned char * pucCntx, const struct pcap_pkthdr*  pstPktHdr, const u_char *pucPacket)
{
	Protocol_parse parse;
	parse.parse(pstPktHdr, pucPacket);

	return ;
}

bool Capture::search_print()
{
	int iRet = 0;
	//1.查找所有的网卡接口
	iRet = pcap_findalldevs(&pstAllDevices, acErrBuff);
	if (iRet != 0)
	{
		cout << "*     Could not find any device! --" << acErrBuff << endl;
		return false;
	}
	
	//2.打印网卡接口列表
	pstDevice = pstAllDevices;
	cout << "*  Device list:" << endl;
	for( int iLoop = 0; pstDevice != NULL; iLoop++)
	{
		if (g_uiDeviceIndex == iLoop)
		{
			cout << "*  -> " << iLoop << ":" << pstDevice->name << ", " << 
				(pstDevice->description != NULL ? pstDevice->description : "NULL")<< endl;
			g_acDeviceName = pstDevice->name;
		}
		else
		{
			cout << "*     " << iLoop << ":" << pstDevice->name << ", " << 
				(pstDevice->description != NULL ? pstDevice->description : "NULL")<< endl;
		}
		pstDevice = pstDevice->next;
	}

	pcap_freealldevs(pstAllDevices);
	pstAllDevices = NULL;

	if (uiShowUsageOnly)
	{
		usage_print();
		return false;
	}
	

	if (g_acDeviceName.empty())
	{
		cout << "*     Could not found the selected device:" << g_uiDeviceIndex << endl;
		return false;
	}

	cout << "*     Select device: " << g_uiDeviceIndex << ", " << g_acDeviceName<< endl;

	return true;
}

void Capture::usage_print()
{	
	cout << "*  Usage:" << endl;
	cout << "*     capture <Device Index> [Filter]" << endl;
	cout << "*     example: capture 5 \"port 80\"" << endl;
	return ;
}

bool Capture::open_interface()
{
	int iRet = 0;
	//3.查询网卡
	iRet = pcap_lookupnet(g_acDeviceName.c_str(), &uiIP, &uiNetmask, acErrBuff);
	if (iRet != 0)
	{
		cout << "*     Could not get the device information! --" << acErrBuff << endl;
		uiIP = 0;
		uiNetmask = 0;
		return false;
	}

	//4.打开指定的网卡
	//参数1.网卡名称 参数2.最大数据长度 参数3.超时时间 参数4.错误信息
	pstHandle = pcap_open_live(g_acDeviceName.c_str(), 65535, 1, 500, acErrBuff);
	if (pstHandle == NULL)
	{
		cout << "*     Could not open device:" << g_acDeviceName << ", " << acErrBuff << endl;
		return false;
	}
	return true;
}

bool Capture::set_filter()
{
	int iRet = 0;
	//5.设置过滤规则
	//参数1.网卡句柄 参数2.过滤器 参数3.过滤条件字符串 参数4.是否优化 参数5.网络掩码
	iRet = pcap_compile(pstHandle, &stFilter, g_acFilter.c_str(), 0, uiNetmask);
	if (iRet != 0)
	{
		cout << "*     Could not parse the filter \"" << g_acFilter << "\", " << 
			pcap_geterr(pstHandle) << endl;
		return false;
	}
	iRet = pcap_setfilter(pstHandle, &stFilter);
	if (iRet != 0)
	{
		cout << "*     Could not set the filter \"" << g_acFilter << "\", " << 
			pcap_geterr(pstHandle)<< endl;
		return false;
	}
	return true;
}

void Capture::capture()
{
	//6.抓包处理
	pcap_loop(pstHandle, -1, traffic_callback, NULL);

	//7.关闭网卡
	pcap_close(pstHandle);
	pstHandle = NULL;

	return ;
}

void Capture::start()
{
	if (!search_print())
	      return;
	if (!open_interface())
	      return ;
	if (!set_filter())
	      return ;
	capture();
}

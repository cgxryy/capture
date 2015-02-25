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

using namespace::std;

//网卡名称最大长度
const int DEVICE_NAME_LEN = 1024;
//过滤条件最大长度
const int FILTER_LEN = 10*1024;

//网卡索引及名称
unsigned char 	g_uiDeviceIndex = -1;
char 		g_acDeviceName[DEVICE_NAME_LEN + 1] = {0};

//条件过滤器
char  		g_acFilter[FILTER_LEN + 1] = {0};

//报文处理回调函数
void traffic_callback(unsigned char *pucCntx, const struct pcap_pkthdr *pskPktHdr, const unsigned char *content);

int main(int argc, char *argv[])
{
	char *pcDev = NULL;
	char acErrBuff[PCAP_ERRBUF_SIZE] = {0};
	int iLoop = 0;

	unsigned int uiShowUsageOnly = 0;
	int iRet = 0;

	pcap_t *pstHandle = NULL;
	pcap_if_t *pstAllDevices = NULL;
	pcap_if_t *pstDevice = NULL;

	struct bpf_program stFilter = {0};
	bpf_u_int32 uiIP = 0;
	bpf_u_int32 uiNetmask = 0;

	if (argc <= 1)
	{
		uiShowUsageOnly = 1;
	}
	else if (argc == 2)
	{
		g_uiDeviceIndex = atoi(argv[1]);
	}
	else 
	{
		g_uiDeviceIndex = atoi(argv[1]);
		strncpy(g_acFilter, argv[2], FILTER_LEN);
		cout << "Set Filter: " << g_acFilter << endl; 
	}

	//1.查找所有的网卡接口
	iRet = pcap_findalldevs(&pstAllDevices, acErrBuff);
	if (iRet != 0)
	{
		cout << "*     Could not find any device! --" << acErrBuff << endl;
		return 1;
	}
	
	//2.打印网卡接口列表
	pstDevice = pstAllDevices;
	cout << "*  Device list:" << endl;
	for( iLoop = 0; pstDevice != NULL; iLoop++)
	{
		if (g_uiDeviceIndex == iLoop)
		{
			cout << "*  -> " << iLoop << ":" << pstDevice->name <<
				", " << (pstDevice->description != NULL ? pstDevice->description : "NULL")<< endl;
			strncpy(g_acDeviceName, pstDevice->name, DEVICE_NAME_LEN);
		}
		else
		{
			cout << "*     " << iLoop << ":" << pstDevice->name <<
				", " << (pstDevice->description != NULL ? pstDevice->description : "NULL")<< endl;
		}
		pstDevice = pstDevice->next;
	}

	pcap_freealldevs(pstAllDevices);
	pstAllDevices = NULL;

	if(uiShowUsageOnly == 1)
	{
		cout << "*  Usage:" << endl;
		cout << "*     " << argv[0] << " <Device Index> [Filter]" << endl;
		cout << "*     example: " << argv[0] << " eth0 \"port 80\"" << endl;
		return 0;
	}

	if (strlen(g_acDeviceName) == 0)
	{
		cout << "*     Could not found the selected device:" << g_uiDeviceIndex << endl;
		return 0;
	}

	cout << "*     Select device: " << g_uiDeviceIndex << ", " << g_acDeviceName<< endl;
	
	//3.查询网卡
	iRet = pcap_lookupnet(g_acDeviceName, &uiIP, &uiNetmask, acErrBuff);
	if (iRet != 0)
	{
		cout << "*     Could not get the device information! --" << acErrBuff << endl;
		uiIP = 0;
		uiNetmask = 0;
		return 1;
	}

	//4.打开指定的网卡
	//参数1.网卡名称 参数2.最大数据长度 参数3.超时时间 参数4.错误信息
	pstHandle = pcap_open_live(g_acDeviceName, 65535, 1, 500, acErrBuff);
	if (pstHandle == NULL)
	{
		cout << "*     Could not open device:" << g_acDeviceName << ", " << acErrBuff << endl;
		return 1;
	}

	//5.设置过滤规则
	//参数1.网卡句柄 参数2.过滤器 参数3.过滤条件字符串 参数4.是否优化 参数5.网络掩码
	iRet = pcap_compile(pstHandle, &stFilter, g_acFilter, 0, uiNetmask);
	if (iRet != 0)
	{
		cout << "*     Could not parse the filter \"" << g_acFilter << "\", " << 
			pcap_geterr(pstHandle) << endl;
		return 1;
	}
	iRet = pcap_setfilter(pstHandle, &stFilter);
	if (iRet != 0)
	{
		cout << "*     Could not set the filter \"" << g_acFilter << "\", " << 
			pcap_geterr(pstHandle)<< endl;
		return 1;
	}

	//6.抓包处理
	pcap_loop(pstHandle, -1, traffic_callback, NULL);

	//7.关闭网卡
	pcap_close(pstHandle);
	pstHandle = NULL;

	return 0;
}

void traffic_callback(unsigned char * pucCntx, const struct pcap_pkthdr*pstPktHdr, const unsigned char *pucPacket)
{
	cout << "receive a packet " << pstPktHdr->len << "bytes..."<< endl;

	return ;
}

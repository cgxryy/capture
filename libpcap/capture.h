// =====================================================================================
// 
//       Filename:  init_capture.h
//
//    Description:  
//
//        Version:  1.0
//        Created:  2015年02月25日 21时49分56秒
//       Revision:  none
//       Compiler:  g++
//
//         Author:  Reazon (Changgongxiaorong), cgxryy@gmail.com
//        Company:  Class 1203 of Network Engineering
// 
// =====================================================================================

#ifndef CAPTURE_H_
#define CAPTURE_H_

#include <string>
#include <pcap.h>

//网卡名称最大长度
const int DEVICE_NAME_LEN = 1024;
//过滤条件最大长度
const int FILTER_LEN = 10*1024;

//报文处理回调函数
void traffic_callback(unsigned char *pucCntx, const struct pcap_pkthdr *pskPktHdr, const unsigned char *content);


class Capture
{
public:
	bool 		uiShowUsageOnly;
	//网卡索引
	unsigned char 	g_uiDeviceIndex;
	//条件过滤器
	std::string  	g_acFilter;
	Capture() : 
		uiShowUsageOnly(false),
		g_uiDeviceIndex(-1),
		pstHandle(NULL),
		pstAllDevices(NULL),
		pstDevice(NULL),
		uiIP(0),
		uiNetmask(0)
	{}
	~Capture(){}

	bool search_print();
	void start();
	
private:
	//网卡名称	
	std::string 	g_acDeviceName;	
	char 		acErrBuff[PCAP_ERRBUF_SIZE];

	pcap_t* 	pstHandle;
	pcap_if_t* 	pstAllDevices;
	pcap_if_t* 	pstDevice;

	struct bpf_program 	stFilter;
	bpf_u_int32 		uiIP;
	bpf_u_int32 		uiNetmask;
	

	void usage_print();
	bool open_interface();
	bool set_filter();
	void capture();

};

#endif 

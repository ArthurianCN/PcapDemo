#include <iostream>
#include <string>
#include <pcap.h>
#include "LogPrint.h"
#include "NetStructDef.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// 解析数据包的回调函数
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
	// 打印包的详细信息
	LOG_INFO("[Capture time: %10ld.%06lds]" "Packet len: %5u, caplen: %5u", 
		header->ts.tv_sec, header->ts.tv_usec, header->len, header->caplen);

	const eth_hdr* ethhdr = (const eth_hdr*)packet;

	const ip_header* iphdr = (const ip_header*)(packet + sizeof(eth_hdr));
	char szSrcIp[IP_ADDR_LENGTH] = { 0 }, szDstIp[IP_ADDR_LENGTH] = { 0 };
	if ((nullptr == inet_ntop(AF_INET, &iphdr->saddr, szSrcIp, sizeof(szSrcIp))) ||
		(nullptr == inet_ntop(AF_INET, &iphdr->daddr, szDstIp, sizeof(szDstIp)))
		)
	{
		return;
	}

	udp_header* udphdr = nullptr;

	switch (iphdr->proto)
	{
	case IPPROTO_UDP:
		udphdr = (udp_header*)(packet + sizeof(eth_hdr) + iphdr->ihl * 4);
		LOG_INFO("%s:%d -> %s:%d", 
			szSrcIp, ntohs(udphdr->sport), szDstIp, ntohs(udphdr->dport));
		LOG_INFO("udp len : %d, payload", ntohs(udphdr->len));
		break;

	case IPPROTO_TCP:

		break;

	default:
		break;
	}
}

int main(int _argc, char* _argv[])
{
	if (_argc < 2)
	{
		return 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	const char* pcap_file_name = _argv[1];  // 要解析的PCAP文件名

	// 打开PCAP文件
	pcap_t* handle = pcap_open_offline(pcap_file_name, errbuf);
	if (handle == nullptr) 
	{
		LOG_ERROR("pcap_open_offline fail. %s", errbuf);
		return 1;
	}

	struct pcap_pkthdr* header = nullptr;
	const u_char* pkt_data = nullptr;
	int res = PCAP_ERROR;  // 解析结果
	// 读取并处理每个数据包
	while ((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) 
	{
		if (res == 0) 
		{
			continue;
		}

		// 调用回调函数处理数据包
		packet_handler(nullptr, header, pkt_data);
	}

	// 检查错误
	if (res == -1) 
	{
		LOG_ERROR("读取PCAP文件时发生错误: %s", pcap_geterr(handle));
		return 1;
	}

	pcap_close(handle);
	LOG_INFO("解析完成");

	return 0;
}
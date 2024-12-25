#pragma once


#define IP_ADDR_LENGTH				16

//Mac头部，总长度14字节
typedef struct _eth_hdr
{
	unsigned char dstmac[6];		// 目标mac地址
	unsigned char srcmac[6];		// 源mac地址
	unsigned short eth_type;		// 以太网类型
}eth_hdr;


/* IPv4 header */
typedef struct ip_header
{
#if 1
	unsigned char ihl : 4;     //首部长度
	unsigned char version : 4; //版本
#else
	unsigned char version : 4; //版本
	unsigned char ihl : 4;     //首部长度
#endif
	unsigned char	tos;			// Type of service 
	unsigned short tlen;			// Total length 
	unsigned short identification;	// Identification
	unsigned short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	unsigned char	ttl;			// Time to live
	unsigned char	proto;			// Protocol
	unsigned short crc;				// Header checksum
	struct in_addr	saddr;			// Source address
	struct in_addr	daddr;			// Destination address
	unsigned int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	unsigned short sport;			// Source port
	unsigned short dport;			// Destination port
	unsigned short len;				// Datagram length
	unsigned short crc;				// Checksum
}udp_header;

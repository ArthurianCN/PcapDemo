#pragma once


#define IP_ADDR_LENGTH				16

//Macͷ�����ܳ���14�ֽ�
typedef struct _eth_hdr
{
	unsigned char dstmac[6];		// Ŀ��mac��ַ
	unsigned char srcmac[6];		// Դmac��ַ
	unsigned short eth_type;		// ��̫������
}eth_hdr;


/* IPv4 header */
typedef struct ip_header
{
#if 1
	unsigned char ihl : 4;     //�ײ�����
	unsigned char version : 4; //�汾
#else
	unsigned char version : 4; //�汾
	unsigned char ihl : 4;     //�ײ�����
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

#ifndef FRAME_H
#define FRAME_H

#include <pcap.h>


#define DATA_SIZE (1500 - sizeof(eth_header) - sizeof(ip_header) - sizeof(udp_header) - 10)


#ifdef WIN32
#pragma pack(push, r1, 1)
#endif


struct ip_address
{
	u_char bytes[4];
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct eth_header
{
	u_char dstmac[6];
	u_char srcmac[6];
	u_short type;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct ip_header
{
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short id;
	u_short flags_foff;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address srcaddr;
	ip_address dstaddr;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct udp_header
{
	u_short srcport;
	u_short dstport;
	u_short len;
	u_short crc;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct data_t
{
	u_int no;
	u_int filesize;
	u_short datasize;
	char data[DATA_SIZE];
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;


struct frame
{
	eth_header eth;
	ip_header  ip;
	udp_header udp;
	data_t     data;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct ack_frame
{
	eth_header eth;
	ip_header ip;
	udp_header udp;
	u_int no;
	u_int mrs[4];
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

#ifdef WIN32
#pragma pack(pop, r1)
#endif

int send_packet(pcap_t *handle, const char *srcmac, const char *dstmac, data_t& data);
int send_ack_packet(pcap_t *handle, const char *srcmac, const char *dstmac, u_int no);


#endif

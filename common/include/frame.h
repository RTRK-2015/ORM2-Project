#ifndef FRAME_H
#define FRAME_H

#include <cstdint>
#include <pcap.h>


#define DATA_SIZE 1400


#ifdef WIN32
#pragma pack(push, r1, 1)
#endif


struct ip_address
{
	std::uint8_t bytes[4];
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct eth_header
{
	std::uint8_t dstmac[6];
	std::uint8_t srcmac[6];
	std::uint16_t type;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct ip_header
{
	std::uint8_t ver_ihl;
	std::uint8_t tos;
	std::uint16_t tlen;
	std::uint16_t id;
	std::uint16_t flags_foff;
	std::uint8_t ttl;
	std::uint8_t proto;
	std::uint16_t crc;
	ip_address srcaddr;
	ip_address dstaddr;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct udp_header
{
	std::uint16_t srcport;
	std::uint16_t dstport;
	std::uint16_t len;
	std::uint16_t crc;
}
#if defined(unix) || defined(__unix) || defined(__unix__)
__attribute__((packed))
#endif
;

struct data_t
{
	std::uint32_t no;
	std::uint32_t filesize;
	std::uint16_t datasize;
	std::uint8_t data[DATA_SIZE];
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

#ifdef WIN32
#pragma pack(pop, r1)
#endif

int send_packet(pcap_t *handle, const char *srcmac, const char *dstmac, data_t data);


#endif

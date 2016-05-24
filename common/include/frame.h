#ifndef FRAME_H
#define FRAME_H

#include <cstdint>


struct ip_address
{
	std::uint8_t bytes[4];
};


struct eth_header
{
	std::uint8_t dstmac[6];
	std::uint8_t srcmac[6];
	std::uint16_t type;
};


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
	std::uint32_t op_pad;
};


struct udp_header
{
	std::uint16_t srcport;
	std::uint16_t dstport;
	std::uint16_t len;
	std::uint16_t crc;
};


struct data_t
{
	std::uint32_t no;
	std::uint8_t data[1024];
	std::uint16_t crc;
};


struct frame
{
	eth_header eth;
	ip_header  ip;
	udp_header udp;
	data_t     data;
};

#endif
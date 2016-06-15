#include "frame.h"
#include <pcap.h>


uint16_t htons1(uint16_t x)
{
	uint16_t y = 0;

	y |= (x & 0x00FF) << 8;
	y |= (x & 0xFF00) >> 8;

	return y;
}


void send_packet(pcap_t *handle, const char *mac, data_t data)
{
	frame f;

	char realmac[6];
	for (int i = 0; i < 6; ++i)
	{
		char hex[3] = "";
		memcpy(hex, mac + 2 * i, 2);
		realmac[i] = (char)strtol(hex, nullptr, 16);
	}

	// ETH
	memset(f.eth.dstmac, 0xff, 6);
	f.eth.srcmac[0] = 0xA0;
	f.eth.srcmac[1] = 0x48;
	f.eth.srcmac[2] = 0x1C;
	f.eth.srcmac[3] = 0x87;
	f.eth.srcmac[4] = 0xB2;
	f.eth.srcmac[5] = 0xA6;
	f.eth.type = htons1(0x0800);

	// IP
	f.ip.ver_ihl = 0x45;
	f.ip.tos = 0;
	f.ip.tlen = htons1(sizeof(frame) - sizeof(eth_header));
	f.ip.id = 0;
	f.ip.flags_foff = 0;
	f.ip.ttl = 0xFF;
	f.ip.proto = 0x11;
	f.ip.crc = htons1(0xDEAD);
	f.ip.srcaddr.bytes[0] = 192;
	f.ip.srcaddr.bytes[1] = 168;
	f.ip.srcaddr.bytes[2] = 56;
	f.ip.srcaddr.bytes[3] = 0;
	memset(&f.ip.dstaddr, 0, 4);
	f.ip.op_pad = 0;

	// UDP
	f.udp.dstport = htons1(1536);
	f.udp.srcport = htons1(2048);
	f.udp.len = htons1(sizeof(udp_header) + sizeof(data_t));
	f.udp.crc = htons1(0xBABE);

	// DATA
	memcpy(&f.data, &data, sizeof(data_t));

	pcap_sendpacket(handle, (const u_char*)&f, sizeof(frame));
}

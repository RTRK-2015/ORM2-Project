#include "frame.h"
#include <pcap.h>


int send_packet(pcap_t *handle, const char *srcmac, const char *dstmac, data_t& data)
{
	frame f;

	char realdstmac[6];
	char realsrcmac[6];

	for (int i = 0; i < 6; ++i)
	{
		char hex[3] = "";
		memcpy(hex, dstmac + 3 * i, 3);
		hex[2] = '\0';
		realdstmac[i] = (char)strtol(hex, nullptr, 16);

		memcpy(hex, srcmac + 3 * i, 3);
		hex[2] = '\0';
		realsrcmac[i] = (char)strtol(hex, nullptr, 16);
	}

	// ETH
	memcpy(&f.eth.dstmac, realdstmac, 6);
	memcpy(&f.eth.srcmac, realsrcmac, 6);
	f.eth.type = htons(0x0800);

	// IP
	f.ip.ver_ihl = 0x45;
	f.ip.tos = 0x00;
	f.ip.tlen = htons(sizeof(frame) - sizeof(eth_header));
	f.ip.id = 0x0000;
	f.ip.flags_foff = 0x0000;
	f.ip.ttl = 0x7F;
	f.ip.proto = 0x11;

	u_int s = 0x4500 + (sizeof(frame) - sizeof(eth_header)) + 0x7F11;
	u_short u = (0xFFFF0000 & s) >> 16;
	s = (s & 0x0000FFFF) + u;
	f.ip.crc = htons(~(u_short)s);

	memset(&f.ip.srcaddr, 0x00, 4);
	memset(&f.ip.dstaddr, 0x00, 4);

	// UDP
	f.udp.srcport = htons(2048);
	f.udp.dstport = htons(1536);
	f.udp.len = htons(sizeof(udp_header) + sizeof(data_t));
	f.udp.crc = htons(0x0000);

	// DATA
	memcpy(&f.data, &data, sizeof(data_t));

	return pcap_sendpacket(handle, (const u_char*)&f, sizeof(frame));
}


int send_ack_packet(pcap_t *handle, const char *srcmac, const char *dstmac, u_int no)
{
	ack_frame f;

	char realdstmac[6];
	char realsrcmac[6];

	for (int i = 0; i < 6; ++i)
	{
		char hex[3] = "";
		memcpy(hex, dstmac + 3 * i, 3);
		hex[2] = '\0';
		realdstmac[i] = (char)strtol(hex, nullptr, 16);

		memcpy(hex, srcmac + 3 * i, 3);
		hex[2] = '\0';
		realsrcmac[i] = (char)strtol(hex, nullptr, 16);
	}

	// ETH
	memcpy(&f.eth.dstmac, realdstmac, 6);
	memcpy(&f.eth.srcmac, realsrcmac, 6);
	f.eth.type = htons(0x0800);

	// IP
	f.ip.ver_ihl = 0x45;
	f.ip.tos = 0x00;
	f.ip.tlen = htons(sizeof(ack_frame) - sizeof(eth_header));
	f.ip.id = 0x0000;
	f.ip.flags_foff = 0x0000;
	f.ip.ttl = 0x7F;
	f.ip.proto = 0x11;

	u_int s = 0x4500 + (sizeof(ack_frame) - sizeof(eth_header)) + 0x7F11;
	u_short u = (0xFFFF0000 & s) >> 16;
	s = (s & 0x0000FFFF) + u;
	f.ip.crc = htons(~(u_short)s);

	memset(&f.ip.srcaddr, 0x00, 4);
	memset(&f.ip.dstaddr, 0x00, 4);

	// UDP
	f.udp.srcport = htons(2048);
	f.udp.dstport = htons(1536);
	f.udp.len = htons(sizeof(udp_header) + sizeof(u_int));
	f.udp.crc = htons(0x0000);

	// DATA
	f.no = no;
	f.mrs = no;

	return pcap_sendpacket(handle, (const u_char*)&f, sizeof(ack_frame));
}

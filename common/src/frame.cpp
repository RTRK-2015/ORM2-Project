#include "frame.h"
#include <pcap.h>


int send_packet(pcap_t *handle, const char *mac, data_t data)
{
	frame f;

	char dstmac[6];
	for (int i = 0; i < 6; ++i)
	{
		char hex[3] = "";
		memcpy(hex, mac + 2 * i, 2);
		dstmac[i] = (char)strtol(hex, nullptr, 16);
	}

	// ETH
	memcpy(&f.eth.dstmac, dstmac, 6);
	f.eth.srcmac[0] = 0xA0;
	f.eth.srcmac[1] = 0x48;
	f.eth.srcmac[2] = 0x1C;
	f.eth.srcmac[3] = 0x8A;
	f.eth.srcmac[4] = 0x21;
	f.eth.srcmac[5] = 0xBA;
	f.eth.type = htons(0x0800);

	// IP
	f.ip.ver_ihl = 0x45;
	f.ip.tos = 0;
	f.ip.tlen = htons(sizeof(frame) - sizeof(eth_header));
	f.ip.id = 0;
	f.ip.flags_foff = 0;
	f.ip.ttl = 0xFF;
	f.ip.proto = 0x11;
	f.ip.crc = htons(0xDEAD);
	memset(&f.ip.srcaddr, 0, 4);
	memset(&f.ip.dstaddr, 0, 4);

	// UDP
	f.udp.srcport = htons(2048);
	f.udp.dstport = htons(1536);
	f.udp.len = htons(sizeof(udp_header) + sizeof(data_t));
	f.udp.crc = htons(0xBABE);

	// DATA
	memcpy(&f.data, &data, sizeof(data_t));

	return pcap_sendpacket(handle, (const u_char*)&f, sizeof(frame));
}

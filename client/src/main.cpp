#include <algorithm>
#include <iostream>
#include <pcap.h>
#include "select_device.h"
#include "thread.h"
#include <string>
#include "mutex.h"
#include <fstream>
#include "frame.h"
#include <vector>
using namespace std;

mutex m;

struct data
{
	pcap_if_t *handle;
	const char* srcmac;
	const char* dstmac;
};

static char *packet_filter;
char* buf = nullptr;
int bufsize = 1;
int full = 0;
const u_int netmask = 0xFFFFFF; 
vector<char> state(1);

void *worker(void *handle)
{
	data d = *(data*) handle;
	int packet_count = 0;
	pcap_pkthdr *header;
	const u_char *pkt_data;
	bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* h = pcap_open_live(d.handle->name, 65536, 1, -1, errbuf);

	int a = pcap_compile(h, &fcode, packet_filter, 1, netmask);
	int b = pcap_setfilter(h, &fcode);

	while (true)
	{
		m.lock();
		if (find(state.cbegin(), state.cend(), 0) == state.cend())
		{
			for (int i = 0; i < 50; ++i)
				send_ack_packet(h, d.srcmac, d.dstmac, (uint32_t)-1);
			return nullptr;
		}
		m.unlock();

		m.lock();
		int a = pcap_next_ex(h, &header, &pkt_data);
		m.unlock();

		if(a < 1)
			continue;

		frame f = *(frame*) pkt_data;

		m.lock();
		packet_count++;
		printf("Received packets %d\n", packet_count);
		m.unlock();

		m.lock();
		if(buf == nullptr)
		{
			
			bufsize = f.data.filesize;
			buf = new char[bufsize];
			state.resize(ceil(bufsize*1.0/DATA_SIZE));

		}
		m.unlock();

		memcpy(buf + DATA_SIZE * f.data.no, f.data.data, f.data.datasize);
		state[f.data.no] = 1;
		int mrs = send_ack_packet(h, d.srcmac, d.dstmac, f.data.no);
	}
	m.unlock();

	return nullptr;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	string filt = "ether dst " + string(argv[2]) + " or ether dst " + string(argv[4]) + " and dst host 0.0.0.0";
	packet_filter = (char*)filt.c_str();


	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_if_t *handle1 = select_device(devs);
	pcap_if_t *handle2 = select_device(devs);


	data d1;
	d1.handle = handle1;
	d1.srcmac = argv[2];
	d1.dstmac = argv[3];


	data d2;
	d2.handle = handle2;
	d2.srcmac = argv[4];
	d2.dstmac = argv[5];
	

	thread th1(worker, (void*)&d1);
	thread th2(worker, (void*)&d2);
	
	th1.join();
	th2.join();

	ofstream file(argv[1], ios::binary);
	file.write(buf, bufsize);

}

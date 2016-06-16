#include <iostream>
#include <pcap.h>
#include "select_device.h"
#include "thread.h"
#include <string>
#include "mutex.h"
#include <fstream>
#include "frame.h"

using namespace std;

mutex m;

struct data
{
	pcap_if_t *handle;
	const char* mac;
};

static const char packet_filter[] = "dst host 0.0.0.0";
char* buf = nullptr;
int bufsize = 1;
int full = 0;
const u_int netmask = 0xFFFFFF; 

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
		if(full == bufsize)
			break;
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
		}
		m.unlock();

		memcpy(buf + DATA_SIZE * f.data.no, f.data.data, f.data.datasize);

		m.lock();
		full += f.data.datasize;
		printf("Bufsize: %d, Full: %d\n", bufsize, full);
		m.unlock();
	}
	m.unlock();

	return nullptr;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	struct bpf_program fcode1, fcode2;


	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_if_t *handle1 = select_device(devs);
	pcap_if_t *handle2 = select_device(devs);


	data d1;
	d1.handle = handle1;
	d1.mac = argv[2];


	data d2;
	d2.handle = handle2;
	d2.mac = argv[2];

	thread th1(worker, (void*)&d1);
	thread th2(worker, (void*)&d2);
	
	th1.join();
	th2.join();

	ofstream file(argv[1], ios::binary);
	file.write(buf, bufsize);

}

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
	pcap_t *handle;
	const char* mac;
};

char* buf = nullptr;
int bufsize;
int full = 0;

void *worker(void *handle)
{
	data d = *(data*) handle;


	pcap_pkthdr *header;
	const u_char *pkt_data;

	while (true)
	{
		int a = pcap_next_ex(d.handle, &header, &pkt_data);
		if(a < 1)
			continue;

		frame f = *(frame*) pkt_data;

		if(buf == nullptr)
		{
			bufsize = f.data.filesize;
			buf = new char[bufsize];
		}

		memcpy(buf + 1024 * f.data.no, f.data.data, f.data.datasize);

		full += f.data.datasize;
		
		if(full == bufsize)
			break;

	}

	return nullptr;
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "dst host 0.0.0.0";
	struct bpf_program fcode1, fcode2;
	u_int netmask = 0xFFFFFF; 

	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_t *handle1 = select_device(devs);
	pcap_t *handle2 = select_device(devs);



	data d1;
	d1.handle = handle1;
	d1.mac = argv[2];
	int a = pcap_compile(handle1, &fcode1, packet_filter, 1, netmask);
	char *err = pcap_geterr(handle1);
	int b = pcap_setfilter(handle1, &fcode1);

	data d2;
	d2.mac = argv[2];
	pcap_compile(handle2, &fcode2, packet_filter, 1, netmask);
	pcap_setfilter(handle2, &fcode2);

	thread th1(worker, (void*)&d1);
	//thread th2(worker, (void*)&d2);
	
	th1.join();
	//th2.join();

	ofstream file(argv[1], ios::binary);
	file.write(buf, bufsize);

}

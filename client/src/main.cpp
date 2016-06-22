#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

#include <cstdint>

#include <pcap.h>

#include "frame.h"
#include "mutex.h"
#include "select_device.h"
#include "thread.h"
#include "delay.h"

#undef max


using namespace std;

mutex m;

struct data
{
	pcap_if_t *handle;
	const char* srcmac;
	const char* dstmac;
	int id;
};

static char *packet_filter;
char* buf = nullptr;
int bufsize = 1;
int full = 0;
const bpf_u_int32 netmask = 0xFFFFFF; 
const int size = 65536;
vector<char> state(1);
clock_t start1;
clock_t start2;
clock_t tp1;
clock_t tp2;

void *worker(void *handle)
{
	data d = *(data*) handle;
	int packet_count = 0;
	int real_packet_count = 0;
	pcap_pkthdr *header;
	const u_char *pkt_data;
	bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	double speed = 0;
	int confirmations = 0;

	pcap_t* h = pcap_open_live(d.handle->name, size, 1, -1, errbuf);

	pcap_compile(h, &fcode, packet_filter, 1, netmask);
	pcap_setfilter(h, &fcode);

	for (;;)
	{
		m.lock();
		if (find(state.cbegin(), state.cend(), 0) == state.cend())
		{
			for (int i = 0; i < 50; ++i)
			{
				delay(5);
				send_ack_packet(h, d.srcmac, d.dstmac, (uint32_t)-1);
			}

			m.unlock();

			float total_time =  1.0 * (clock() - (d.id == 1? start1 : start2))/ CLOCKS_PER_SEC;
			printf("Total time:  %f, Avg speed: %f\n", total_time, packet_count * DATA_SIZE / total_time / 1024);
			return nullptr;
		}
		m.unlock();

		int err = pcap_next_ex(h, &header, &pkt_data);

		if(err == 0)
			continue;
		if (err == -1)
		{
			h = nullptr;

			do
			{
				cout << "Sir... SIIIIIIIIIIR\n";
				cin.ignore(numeric_limits<streamsize>::max(), '\n');
				h = pcap_open_live(d.handle->name, size, 1, -1, errbuf);
			} while (h == nullptr);

			pcap_compile(h, &fcode, packet_filter, 1, netmask);
			pcap_setfilter(h, &fcode);
		}

		frame f = *(frame*) pkt_data;

		const int packets = 200;		
		if((packet_count + 1) % packets == 0)
		{
			speed = ((1.0 * packets * DATA_SIZE) / (1.0 * (clock() - (d.id == 1? tp1 : tp2)) / CLOCKS_PER_SEC)) / 1024;
			(d.id == 1? tp1 : tp2) = clock();
		}

		printf("Received packets %d, Speed (kBps): %f, Confirmations: %d\n", ++packet_count, speed, confirmations);

		m.lock();
		if(buf == nullptr)
		{
			
			bufsize = f.data.filesize;
			buf = new char[bufsize];
			state.resize((unsigned)ceil(bufsize*1.0/DATA_SIZE));
			tp1 = clock();
			tp2 = clock();
			start1 = clock();
			start2 = clock();
		}
		m.unlock();

		memcpy(buf + DATA_SIZE * f.data.no, f.data.data, f.data.datasize);
		if(state[f.data.no] == 0)
			++real_packet_count;
		state[f.data.no] = 1;
		err = send_ack_packet(h, d.srcmac, d.dstmac, f.data.no);
		if(err != -1)
			++confirmations;

		if (err == -1)
		{
			h = nullptr;

			do
			{
				cout << "Sir... SIIIIIIIIIIR\n";
				cin.ignore(numeric_limits<streamsize>::max(), '\n');
				h = pcap_open_live(d.handle->name, size, 1, -1, errbuf);
			} while (h == nullptr);

			pcap_compile(h, &fcode, packet_filter, 1, netmask);
			pcap_setfilter(h, &fcode);
		}
	}
}

int main(int argc, char *argv[])
{
	printf("Ack_frame: %d\n", sizeof(ack_frame));
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
	d1.id = 1;


	data d2;
	d2.handle = handle2;
	d2.srcmac = argv[4];
	d2.dstmac = argv[5];
	d2.id = 2;
	

	thread th1(worker, (void*)&d1);
	thread th2(worker, (void*)&d2);
	
	th1.join();
	th2.join();

	ofstream file(argv[1], ios::binary);
	file.write(buf, bufsize);

}

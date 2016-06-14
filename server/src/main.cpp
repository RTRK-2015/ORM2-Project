#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <pcap.h>
#include "select_device.h"
#include "thread.h"
#include "mutex.h"
#include "helper.h"
#include "frame.h"

using namespace std;


enum SendState
{
	UNSENT = 0,
	SENT,
	CONFIRMED
};

struct Data
{
	pcap_t *handle;
	const char *mac;
	vector<SendState> state;
};


mutex m;



void* worker(void *handle)
{
	Data data = *(Data*)handle;

	return nullptr;
}



int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	/*ifstream file(argv[1], ios::binary);
	auto size = filesize(argv[1]);*/
	
	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_t *handle1 = select_device(devs);
	pcap_t *handle2 = select_device(devs);

	vector<Data> data;
	vector<thread> threads;
	vector<vector<SendState>> state;

	data_t d;
	d.crc = 0xB00B;
	d.no = 0x55555555;
	strcpy((char *)d.data, "Hello, fucktards");

	send_packet(handle1, "A0481C87B1E5", d);
	/*for (int i = 2; i < argc; ++i)
	{
		state.push_back(vector<SendState>(size / 1024));

		Data d1 = { handle1, argv[i], state[i - 2] };
		data.push_back(d1);

		Data d2 = { handle2, argv[i], state[i - 2] };
		data.push_back(d2);

		threads.push_back(thread(worker, (void*)&data[i]));
		threads.push_back(thread(worker, (void*)&data[i + 1]));
	}

	for (auto it = threads.begin(); it != threads.end(); ++it)
		it->join();*/
}

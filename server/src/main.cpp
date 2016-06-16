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
	int id;
	pcap_if_t *handle;
	const char *srcmac;
	const char *dstmac;
	vector<pair<int, SendState>>& state;
	string filename;
	size_t size;
};


mutex m;

static const char filter[] = "dst host 0.0.0.0";


void handler(u_char *user, const struct pcap_pkthdr *h, const uint8_t *bytes)
{
	m.lock();
	auto v = (vector<pair<int, SendState>>*)user;

	ack_frame *f = (ack_frame*)bytes;
	(*v)[f->no].second = CONFIRMED;

	m.unlock();
}


void* worker(void *handle)
{
	static char errbuf[PCAP_ERRBUF_SIZE];
	bpf_program fcode;

	Data data = *(Data*)handle;
	ifstream file(data.filename, ios::binary);

	pcap_t *h = pcap_open_live(data.handle->name, 65536, 1, -1, errbuf);
	pcap_compile(h, &fcode, filter, 1, 0xFFFFFF);
	pcap_setfilter(h, &fcode);
	pcap_loop(h, -1, handler, (u_char*)&data.state);

	auto sent = 0;

	while (true)
	{
		m.lock();
		auto it = find_if(data.state.begin(), data.state.end(), [](const pair<int, SendState>& s)
		{
			return s.first == 0 && s.second == UNSENT;
		});
		if (it == data.state.end())
			break;
		it->second = SENT;
		m.unlock();

		auto idx = distance(data.state.begin(), it);
		file.seekg(DATA_SIZE * idx);

		data_t d;
		d.no = idx;
		d.filesize = data.size;
		file.read((char*)&d.data, DATA_SIZE);
		d.datasize = file.gcount();

		int a = send_packet(h, data.srcmac, data.dstmac, d);

		m.lock();
		++sent;
		printf("a: %d, Handle %X, sent: %d\n", a, data.handle, sent);
		m.unlock();

		volatile int i;
		for (int x = 0; x < 500000; ++x)
			i = x;
	}

	return nullptr;
}



int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	auto size = filesize(argv[1]);
	
	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_if_t *handle1 = select_device(devs);
	pcap_if_t *handle2 = select_device(devs);

	vector<Data> data;
	vector<thread> threads;
	vector<vector<pair<int, SendState>>> state;

	for (int i = 2; i < argc - 3; ++i)
	{
		state.push_back(vector<pair<int, SendState>>(ceil(size / (DATA_SIZE * 1.0))));

		Data d1 = { 1, handle1, argv[2], argv[2 * i], state[i - 2], argv[1], size };
		data.push_back(d1);

		Data d2 = { 2, handle2, argv[3], argv[2 * i + 1], state[i - 2], argv[1], size };
		data.push_back(d2);

		threads.emplace_back(thread(worker, (void*)&data[i - 2]));
		threads.emplace_back(thread(worker, (void*)&data[i - 2 + 1]));
	}

	for (auto it = threads.begin(); it != threads.end(); ++it)
		it->join();

	pcap_freealldevs(devs);
}

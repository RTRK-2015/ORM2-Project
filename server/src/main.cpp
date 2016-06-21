#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <pcap.h>
#include <ctime>
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

struct State
{
	SendState ss;
	time_t stamp;
};

struct Data
{
	pcap_if_t *handle;
	const char *srcmac;
	const char *dstmac;
	vector<State>& state;
	string filename;
	size_t size;
	mutex& m;
};

struct HandlerData
{
	pcap_t **handle;
	vector<State>& state;
	mutex& m;
};


void* handler(void *hdata)
{
	auto data = *(HandlerData*)hdata;
	pcap_pkthdr *hdr;
	const u_char *pkt_data;

	while (true)
	{
		/*if (find_if(
			data.state.cbegin(), 
			data.state.cend(), 
			[](const State& s) { return s.ss != CONFIRMED; }) == data.state.cend()
			)
			break;*/

		auto err = data.handle != nullptr? pcap_next_ex(*data.handle, &hdr, &pkt_data) : 0;
		if (err < 1)
			continue;

		data.m.lock();

		auto frame = (ack_frame*)pkt_data;
		 
		if (frame->no == (uint32_t)-1)
		{
			for (auto it = data.state.begin(); it != data.state.end(); ++it)
				it->ss = CONFIRMED;

			data.m.unlock();
			return nullptr;
		}
		else
		{
			data.state[frame->no].ss = CONFIRMED;
		}

		data.m.unlock();
	}
}


void* worker(void *handle)
{
	static char errbuf[PCAP_ERRBUF_SIZE];
	bpf_program fcode;

	Data data = *(Data*)handle;
	ifstream file(data.filename, ios::binary);

	pcap_t *h = pcap_open_live(data.handle->name, 65536, 1, -1, errbuf);

	string filter = "ether src " + string(data.dstmac) + " and src host 0.0.0.0";

	pcap_compile(h, &fcode, filter.c_str(), 1, 0xFFFFFF);
	pcap_setfilter(h, &fcode);

	HandlerData hdata = { &h, data.state, data.m };
	thread handlerth(handler, (void*)&hdata);

	auto sent = 0;
	auto tp = time(nullptr);

	while (true)
	{
		data.m.lock();
		auto it = find_if(data.state.begin(), data.state.end(), [&data, &tp](const State& s)
		{
			return (s.ss == UNSENT) || (s.ss != CONFIRMED && difftime(time(nullptr), tp) > 2);
		});
		if (it == data.state.end())
			break;
		it->ss = SENT;
		it->stamp = time(nullptr);
		data.m.unlock();

		auto idx = distance(data.state.begin(), it);
		file.seekg(DATA_SIZE * idx);

		data_t d;
		d.no = idx;
		d.filesize = data.size;
		file.read((char*)&d.data, DATA_SIZE);
		d.datasize = file.gcount();

		int err = send_packet(h, data.srcmac, data.dstmac, d);

		++sent;
		printf("err: %d, sent: %d\n", err, sent);
		if (err == -1)
		{
			do
			{
				printf("Sir... SIIIIIIIIIIR");
				int d;
				scanf("%d", &d);
				h = pcap_open_live(data.handle->name, 65536, 1, -1, errbuf);
			} while (h == nullptr);

			pcap_compile(h, &fcode, filter.c_str(), 1, 0xFFFFFF);
			pcap_setfilter(h, &fcode);
		}
	}

	data.m.unlock();

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
	vector<mutex> mutexes;
	vector<vector<State>> state;

	for (int i = 2; i < argc - 3; ++i)
	{
		state.emplace_back(vector<State>(ceil(size / (DATA_SIZE * 1.0))));
		mutexes.emplace_back(mutex());

		data.emplace_back(
			{ /* pcap handle */handle1
			, /* srcmac eth */ argv[2]
			, /* dstmac eth */ argv[2 * i]
			, /* state vector ref */ state[i - 2]
			, /* file */ argv[1]
			, /* file size */ size
			, /* mutex ref */ mutexes[i - 2]
			});

		data.push_back(
			{ /* pcap handle */ handle2
			, /* srcmac wlan */ argv[3]
			, /* dstmac wlan */ argv[2 * i + 1]
			, /* state vector ref */ state[i - 2]
			, /* file */ argv[1]
			, /* file size */ size
			, /* mutex ref*/ mutexes[i - 2]
			});

		threads.emplace_back(thread(worker, (void*)&data[i - 2]));
		threads.emplace_back(thread(worker, (void*)&data[i - 2 + 1]));
	}

	for (auto it = threads.begin(); it != threads.end(); ++it)
		it->join();

	pcap_freealldevs(devs);
}

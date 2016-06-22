#include <algorithm>
#include <fstream>
#include <limits>
#include <iostream>
#include <vector>

#include <ctime>

#include <pcap.h>

#include "delay.h"
#include "frame.h"
#include "helper.h"
#include "mutex.h"
#include "select_device.h"
#include "thread.h"

#undef max

using namespace std;


enum SendState
{
	UNSENT,
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


int kurac;
bool handlerend = false;


void* handler(void *hdata)
{
	auto data = *reinterpret_cast<HandlerData*>(hdata);
	pcap_pkthdr *hdr = nullptr;
	const u_char *pkt_data = nullptr;

	for (;;)
	{
		data.m.lock();
		if (handlerend)
		{
			data.m.unlock();
			return nullptr;
		}
		data.m.unlock();

		auto err = pcap_next_ex(*data.handle, &hdr, &pkt_data);
		if (err < 1)
			continue;
	
		auto frame = reinterpret_cast<const ack_frame*>(pkt_data);
		 
		if (frame->no != frame->mrs)
		{
			throw "JEBOTE KURAC, KAJ JE OVO";
		}

		data.m.lock();
		if (frame->no == static_cast<u_int>(-1))
		{
			cout << "Received -1 end" << endl;
			handlerend = true;

			for_each(data.state.begin(), data.state.end(), [] (State& s)
				{
					s.ss = CONFIRMED;
				});

			data.m.unlock();
			return nullptr;
		}
		else if (frame->no < data.state.size())
		{
			data.state[frame->no].ss = CONFIRMED;
			++kurac;
		}
		else
		{
			cout << frame->no << endl;
		}

		data.m.unlock();
	}
}


void* worker(void *handle)
{
	static char errbuf[PCAP_ERRBUF_SIZE];
	static const bpf_u_int32 NETMASK = 0xFFFFFF;
	static const int SIZE = numeric_limits<u_short>::max();

	auto data = *reinterpret_cast<Data*>(handle);
	ifstream file(data.filename, ios::binary);
	pcap_t *h = pcap_open_live(data.handle->name, SIZE, 1, -1, errbuf);

	string filter = "ether src " + string(data.dstmac) + " and src host 0.0.0.0";
	bpf_program fcode;
	pcap_compile(h, &fcode, filter.c_str(), 1, NETMASK);
	pcap_setfilter(h, &fcode);

	HandlerData hdata = { &h, data.state, data.m };
	thread handlerth(handler, reinterpret_cast<void*>(&hdata));

	auto sent = 0;

	auto tp = time(nullptr);

	for (;;)
	{
		data.m.lock();
		if (find_if(data.state.cbegin(), data.state.cend(), [](const State& s)
			{
				return s.ss != CONFIRMED;
			}) == data.state.cend())
		{
			cout << "Received all" << endl;
			break;
		}
		
		auto it = find_if(data.state.begin(), data.state.end(), [&data, &tp](const State& s)
		{
			return (s.ss == UNSENT) || (s.ss != CONFIRMED && difftime(time(nullptr), tp) > 5);
		});
		if (it == data.state.end())
		{
			delay(100);
			continue;
		}

		it->ss = SENT;
		it->stamp = time(nullptr);
		data.m.unlock();

		auto idx = distance(data.state.begin(), it);
		file.seekg(DATA_SIZE * idx);

		data_t d;
		d.no = idx;
		d.filesize = data.size;
		file.read(d.data, DATA_SIZE);
		d.datasize = static_cast<u_short>(file.gcount());

		auto err = send_packet(h, data.srcmac, data.dstmac, d);

		++sent;
		cout << "err: " << err << ", sent: " << sent << "\n";
		if (err == -1)
		{
			do
			{
				cout << "Sir... SIIIIIIIIIIR\n";
				cin.ignore(numeric_limits<streamsize>::max(), '\n');
				h = pcap_open_live(data.handle->name, SIZE, 1, -1, errbuf);
			} while (h == nullptr);

			pcap_compile(h, &fcode, filter.c_str(), 1, NETMASK);
			pcap_setfilter(h, &fcode);
		}

		const auto DELAY_AFTER = 50;
		if ((sent + 1) % DELAY_AFTER == 0)
			delay(2);
	}

	data.m.unlock();

	return nullptr;
}



int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	const auto size = static_cast<size_t>(filesize(argv[1]));
	const auto padded_size = static_cast<decltype(size)>(ceil(size * 1.0 / DATA_SIZE));

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
		state.emplace_back(vector<State>(padded_size));
		mutexes.emplace_back(mutex());

		Data d1 = { handle1, argv[2], argv[2 * i], state[i - 2], argv[1], static_cast<size_t>(size), mutexes[i - 2] };
		data.emplace_back(d1);

		Data d2 = { handle2, argv[3], argv[2 * i + 1], state[i - 2], argv[1], static_cast<size_t>(size), mutexes[i - 2] };
		data.emplace_back(d2);

		threads.emplace_back(thread(worker, reinterpret_cast<void*>(&data[i - 2])));
		//threads.emplace_back(thread(worker, reinterpret_cast<void*>(&data[i - 2 + 1])));
	}

	for_each(threads.begin(), threads.end(), [] (thread& th)
		{
			th.join();
		});

	cout << kurac << endl;
	pcap_freealldevs(devs);
}

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
	string filename;
	size_t size;
};


mutex m;



void* worker(void *handle)
{
	Data data = *(Data*)handle;
	ifstream file(data.filename, ios::binary);

	while (true)
	{
		m.lock();
		auto it = find(data.state.begin(), data.state.end(), UNSENT);
		if (it == data.state.end())
			break;
		*it = CONFIRMED;
		m.unlock();

		auto idx = distance(data.state.begin(), it);
		file.seekg(DATA_SIZE * idx);

		data_t d;
		d.no = idx;
		d.filesize = data.size;
		file.read((char*)&d.data, DATA_SIZE);
		d.datasize = file.gcount();

		int a = send_packet(data.handle, data.mac, d);
	}

	return nullptr;
}



int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	auto size = filesize(argv[1]);
	
	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_t *handle1 = select_device(devs);
	pcap_t *handle2 = select_device(devs);

	vector<Data> data;
	vector<thread> threads;
	vector<vector<SendState>> state;

	for (int i = 2; i < argc; ++i)
	{
		state.push_back(vector<SendState>(ceil(size / DATA_SIZE * 1.0)));

		Data d1 = { handle1, argv[i], state[i - 2], argv[1], size };
		data.push_back(d1);

		Data d2 = { handle2, argv[i], state[i - 2], argv[1], size };
		data.push_back(d2);

		threads.emplace_back(thread(worker, (void*)&data[i - 2]));
		//threads.emplace_back(thread(worker, (void*)&data[i - 2 + 1]));
	}

	for (auto it = threads.begin(); it != threads.end(); ++it)
		it->join();
}

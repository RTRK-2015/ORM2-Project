#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <pcap.h>
#include "select_device.h"
#include "thread.h"
#include "mutex.h"

using namespace std;


enum SendState : char
{
	UNSENT,
	SENT,
	CONFIRMED
};


mutex m;
vector<SendState> state;


void* worker(void *handle)
{
	vector<size_t> indices;
	size_t offset = 0;

	while (true)
	{
		m.lock();
		auto it = find(begin(state) + offset, end(state), UNSENT);

		if (it == end(state))
			break;

		*it = SENT;
		m.unlock();

		indices.push_back(distance(begin(state), it));
		offset = indices[indices.size() - 1];
	}

	cout << indices.size() << endl;
	return nullptr;
}


std::streampos filesize(const char* filePath)
{
    std::streampos fsize = 0;
    std::ifstream file(filePath, ios::binary);

    fsize = file.tellg();
    file.seekg(0, ios::end);
    fsize = file.tellg() - fsize;

    return fsize;
}


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	ifstream file(argv[2], ios::binary);
	auto size = filesize(argv[2]);
	state.resize(size, UNSENT);
	
	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_t *handle1 = select_device(devs);
	pcap_t *handle2 = select_device(devs);

	thread th1(worker, (void*)handle1);
	thread th2(worker, (void*)handle2);

	th1.join();
	th2.join();

	int a = 3;
}

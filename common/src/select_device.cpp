#include <iostream>
#include "select_device.h"

using namespace std;


pcap_t* select_device(pcap_if_t *devs)
{
	while (true)
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		cout << "Available devices:" << endl;

		size_t i = 0;
		for (pcap_if_t *walker = devs; walker; walker = walker->next, ++i)
			cout << "[" << i << "] " << walker->name << " (" << walker->description << ")" << endl;
	
		size_t pick = -1;
		while (pick > i - 1)
		{
			cout << "Pick device [0 - " << i - 1 << "]: ";
			cin >> pick;
		}

		for (; pick > 0; devs = devs->next, --pick);
		pcap_t *handle = pcap_open_live(devs->name, 65536, 0, 1000, errbuf); 

		if (handle == nullptr)
		{
			cerr << "Cannot open target device!" << endl;
			continue;
		}
		else
		{
			cout << endl;
			return handle;
		}
	}
}

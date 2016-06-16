#include <iostream>
#include "select_device.h"

using namespace std;


pcap_if_t* select_device(pcap_if_t *devs)
{
	while (true)
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		cout << "Available devices:" << endl;

		size_t i = 0;
		for (pcap_if_t *walker = devs; walker; walker = walker->next, ++i)
		{
			cout << "[" << i << "] " << walker->name << " ";

			if (walker->description != nullptr)
				cout << "(" << walker->description << ")";

			cout << endl;
		}

		size_t pick = (size_t)-1;
		while (pick > i - 1)
		{
			cout << "Pick device [0 - " << i - 1 << "]: ";
			cin >> pick;
		}

		for (; pick > 0; devs = devs->next, --pick);
		return devs;
	}
}

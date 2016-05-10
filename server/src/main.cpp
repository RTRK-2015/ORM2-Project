#include <iostream>
#include <pcap.h>
#include "select_device.h"
#include "thread.h"

using namespace std;


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_t *handle1 = select_device(devs);
	pcap_t *handle2 = select_device(devs);
}

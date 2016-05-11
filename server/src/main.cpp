#include <iostream>
#include <pcap.h>
#include "select_device.h"
#include "thread.h"
#include "mutex.h"

using namespace std;


mutex m;


void* worker(void *handle)
{
  m.lock();
  cout << "Hello " << endl;
  m.unlock();
  return nullptr;
}


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *devs;
	pcap_findalldevs(&devs, errbuf);

	pcap_t *handle1 = select_device(devs);
	pcap_t *handle2 = select_device(devs);

  thread th1(worker, (void*)handle1);
  thread th2(worker, (void*)handle2);

  th1.join();
  th2.join();
}

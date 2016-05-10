#ifndef SELECT_DEVICE
#define SELECT_DEVICE


#include <pcap.h>


pcap_t* select_device(pcap_if_t *devs);


#endif

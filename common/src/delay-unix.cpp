#include "delay.h"

#if U_WOT_M8_MODE == 1 && (defined(unix) || defined(__unix) || defined(__unix__))
#include <unistd.h>

void delay(unsigned millis)
{
	usleep(millis);
}

#endif

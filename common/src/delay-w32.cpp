#include "delay.h"

#if U_WOT_M8_MODE == 1 && (defined(WIN32) || defined(_WIN32))
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <Windows.h>


void delay(unsigned millis)
{
	Sleep(millis);
}


#endif

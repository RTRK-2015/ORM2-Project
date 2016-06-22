#include "mutex.h"

#if U_WOT_M8_MODE == 1 && (defined(WIN32) || defined(_WIN32))
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <Windows.h>
#include <memory>

using namespace std;


struct mutex::impl
{
  HANDLE h;

  impl()
  {
	h = CreateMutex(nullptr, FALSE, nullptr);
  }

  ~impl()
  {
    CloseHandle(h);
  }
};


mutex::mutex()
  : pimpl(new mutex::impl())
{

}


mutex::mutex(mutex&& src)
	: pimpl(src.pimpl.release())
{
}


mutex::~mutex()
{
}


void mutex::lock()
{
	while (WaitForSingleObject(pimpl->h, INFINITE) != 0);
}


void mutex::unlock()
{
	ReleaseMutex(pimpl->h);
}


#endif

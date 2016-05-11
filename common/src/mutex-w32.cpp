#if defined(WIN32) || defined(_WIN32)
#include "mutex.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


struct mutex::impl
{
  HANDLE m;

  impl()
  {
    m = CreateMutex(nullptr, FALSE, nullptr);
  }

  ~impl()
  {
    CloseHandle(m);
  }
};


mutex::mutex()
  : pimpl(new mutex::impl())
{

}


mutex::~mutex()
{
}


void mutex::lock()
{
  WaitForSingleObject(pimpl->m, 0);
}


void mutex::unlock()
{
  ReleaseMutex(pimpl->m);
}


#endif

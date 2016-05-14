#if U_WOT_M8_MODE == 1 && (defined(WIN32) || defined(_WIN32))
#include "mutex.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <memory>

using namespace std;


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
  : pimpl(make_unique<mutex::impl>())
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

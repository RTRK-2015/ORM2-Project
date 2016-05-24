#include "thread.h"

#ifdef U_WOT_M8_MODE == 1 && (defined(WIN32) || defined(_WIN32))
#include "thread.h"
#include <Windows.h>
#include <memory>

using namespace std;


struct thread::impl
{
  HANDLE th;

  impl(void* (*f)(void *), void *data)
  {
    th = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)f, data, 0, nullptr);
  }

  ~impl()
  {
    CloseHandle(th);
  }
};


thread::thread(void* (*f)(void *), void *data)
  : pimpl(new thread::impl(f, data))
{
}


thread::~thread()
{
}


void thread::join()
{
  WaitForSingleObject(pimpl->th, INFINITE);
}


#endif

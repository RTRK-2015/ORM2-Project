#ifdef WIN32
#include "thread.h"
#include <Windows.h>


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
  : pimpl(new impl(f, data))
{
}


thread::~thread()
{
}


void thread::join()
{
  WaitForSingleObject(pimpl->th, 0);
}


#endif

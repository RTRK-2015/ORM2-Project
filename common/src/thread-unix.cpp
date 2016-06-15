#if U_WOT_M8_MODE == 1 && (defined(unix) || defined(__unix) || defined(__unix__))
#include "thread.h"
#include <pthread.h>


struct thread::impl
{
  pthread_t th;

  impl(void* (*f)(void *), void *data)
  {
    pthread_create(&th, nullptr, f, data);
  }
};


thread::thread(void* (*f)(void *), void *data)
  : pimpl(new thread::impl(f, data))
{
}

thread::thread(thread&& src)
	: pimpl(src.pimpl.release())
{
}

thread::~thread()
{
}


void thread::join()
{
  pthread_join(pimpl->th, nullptr);
}


#endif

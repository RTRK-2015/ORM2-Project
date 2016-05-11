#ifdef unix
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


thread::~thread()
{
}


void thread::join()
{
  pthread_join(pimpl->th, nullptr);
}


#endif

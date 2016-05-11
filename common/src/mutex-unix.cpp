#if defined(unix) || defined(__unix) || defined(__unix__)
#include "mutex.h"
#include <pthread.h>


struct mutex::impl
{
  pthread_mutex_t m;

  impl()
  {
    pthread_mutex_init(&m, nullptr);
  }

  ~impl()
  {
    pthread_mutex_destroy(&m);
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
  pthread_mutex_lock(&pimpl->m);
}


void mutex::unlock()
{
  pthread_mutex_unlock(&pimpl->m);
}


#endif
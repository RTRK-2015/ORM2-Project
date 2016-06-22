#ifndef MUTEX_H
#define MUTEX_H


#include <configure.h>


#if U_WOT_M8_MODE == 0
#include <mutex>
#else
#include <memory>


class mutex
{
public:
  mutex();
  mutex(mutex&& src);
  ~mutex();

  void lock();
  void unlock();

private:
  struct impl;
  std::unique_ptr<impl> pimpl;
};


#endif
#endif

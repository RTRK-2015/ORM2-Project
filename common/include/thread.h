#ifndef THREAD_H
#define THREAD_H


#include <configure.h>


#if U_WOT_M8_MODE == 0
#include <thread>
#else
#include <memory>


class thread
{
public:
  thread(void* (*)(void *), void *);
  ~thread();

  void join();


private:
  struct impl;
  std::unique_ptr<impl> pimpl;
};


#endif
#endif

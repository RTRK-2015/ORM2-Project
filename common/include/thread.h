#ifndef THREAD_H
#define THREAD_H


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

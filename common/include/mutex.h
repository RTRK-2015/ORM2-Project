#ifndef MUTEX_H
#define MUTEX_H


#include <memory>


class mutex
{
public:
  mutex();
  ~mutex();

  void lock();
  void unlock();

private:
  struct impl;
  std::unique_ptr<impl> pimpl;
};


#endif

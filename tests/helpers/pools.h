#pragma once

#include <boost/asio/thread_pool.hpp>

#include "core/task.h"

// The pools the service suspends on, for tests: one shared pool of real threads, so work
// handed to it runs elsewhere and comes back, as in the service.
inline lugh::Executor test_pool() {
  static boost::asio::thread_pool pool(2);
  return pool.get_executor();
}

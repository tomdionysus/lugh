//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include "lugh/core/task.h"

// The pools the service suspends on, for tests: one shared pool of real threads, so work
// handed to it runs elsewhere and comes back, as in the service.
inline boost::asio::thread_pool& test_pool_itself() {
  static boost::asio::thread_pool pool(2);
  return pool;
}

inline lugh::Executor test_pool() { return test_pool_itself().get_executor(); }

// Its threads are joined once the last test is done, before the process's own teardown: a
// thread that outlives OpenSSL's cleanup at exit leaves its per-thread random state behind,
// which LeakSanitizer reports (found on Linux, 2026-11-14).
class TestPoolJoin : public ::testing::Environment {
 public:
  void TearDown() override {
    test_pool_itself().stop();
    test_pool_itself().join();
  }
};

inline ::testing::Environment* const kTestPoolJoin = ::testing::AddGlobalTestEnvironment(new TestPoolJoin);

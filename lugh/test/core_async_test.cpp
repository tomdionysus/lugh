//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <atomic>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <thread>
#include <vector>

#include "lugh/core/async_mutex.h"
#include "lugh/core/task.h"
#include "lugh/test/fixtures/run.h"

using lugh::AsyncMutex;
using lugh::Task;

TEST(Offload, RunsElsewhereAndComesBack) {
  boost::asio::thread_pool pool(1);
  const auto here = std::this_thread::get_id();
  const auto [there, back] = run([&]() -> Task<std::pair<std::thread::id, std::thread::id>> {
    const auto on_pool = co_await lugh::offload(pool.get_executor(), [] { return std::this_thread::get_id(); });
    co_return std::make_pair(on_pool, std::this_thread::get_id());
  }());
  EXPECT_NE(there, here);
  EXPECT_EQ(back, here);
  pool.join();
}

TEST(Offload, VoidWorkAndExceptions) {
  boost::asio::thread_pool pool(1);
  int done = 0;
  run(lugh::offload(pool.get_executor(), [&] { ++done; }));
  EXPECT_EQ(done, 1);
  EXPECT_THROW(run(lugh::offload(pool.get_executor(), []() -> int { throw std::runtime_error("x"); })), std::runtime_error);
  pool.join();
}

TEST(AsyncMutex, OneAtATimeInTurn) {
  boost::asio::io_context io;
  AsyncMutex mutex;
  std::vector<int> order;
  int inside = 0;
  int most_inside = 0;

  for (int i = 0; i < 5; ++i) {
    boost::asio::co_spawn(
        io,
        [&, i]() -> Task<void> {
          auto guard = co_await mutex.lock();
          ++inside;
          most_inside = std::max(most_inside, inside);
          // Suspends while holding the lock, as a store write does on its append.
          boost::asio::steady_timer timer(io, std::chrono::milliseconds(1));
          co_await timer.async_wait(boost::asio::use_awaitable);
          order.push_back(i);
          --inside;
        },
        boost::asio::detached);
  }
  io.run();
  EXPECT_EQ(most_inside, 1);
  EXPECT_EQ(order, (std::vector<int>{0, 1, 2, 3, 4}));
}

TEST(AsyncMutex, AcrossThreads) {
  boost::asio::thread_pool pool(4);
  AsyncMutex mutex;
  std::atomic<int> inside{0};
  std::atomic<int> most{0};
  int counter = 0;
  for (int i = 0; i < 200; ++i) {
    boost::asio::co_spawn(
        pool,
        [&]() -> Task<void> {
          auto guard = co_await mutex.lock();
          const auto now = ++inside;
          int seen = most.load();
          while (now > seen && !most.compare_exchange_weak(seen, now)) {
          }
          ++counter;
          --inside;
        },
        boost::asio::detached);
  }
  pool.join();
  EXPECT_EQ(counter, 200);
  EXPECT_EQ(most, 1);
}

TEST(AsyncMutex, AGuardReleasesEarly) {
  AsyncMutex mutex;
  run([&]() -> Task<void> {
    auto first = co_await mutex.lock();
    first.release();
    auto second = co_await mutex.lock();
  }());
}

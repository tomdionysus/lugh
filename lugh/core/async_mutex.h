//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <deque>
#include <mutex>

#include "lugh/core/task.h"

namespace lugh {

// Mutual exclusion for coroutines: a writer that must wait for another suspends, holding
// no thread, and is resumed on its own executor when the lock is its. First come, first
// served. A std::mutex is never held across a co_await; this is what is held instead.
class AsyncMutex {
 public:
  // Releases the lock when it goes, on whatever thread that is.
  class Guard {
   public:
    Guard() = default;
    explicit Guard(AsyncMutex* mutex) : _mutex(mutex) {}
    Guard(Guard&& other) noexcept : _mutex(other._mutex) { other._mutex = nullptr; }
    Guard& operator=(Guard&& other) noexcept {
      if (this != &other) {
        release();
        _mutex = other._mutex;
        other._mutex = nullptr;
      }
      return *this;
    }
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    ~Guard() { release(); }

    void release() {
      if (_mutex != nullptr) _mutex->_unlock();
      _mutex = nullptr;
    }

   private:
    AsyncMutex* _mutex = nullptr;
  };

  AsyncMutex() = default;
  AsyncMutex(const AsyncMutex&) = delete;
  AsyncMutex& operator=(const AsyncMutex&) = delete;

  Task<Guard> lock() {
    // Resumed on the waiter's own executor, whichever thread hands the lock on.
    auto executor = co_await boost::asio::this_coro::executor;
    co_await boost::asio::async_initiate<decltype(boost::asio::use_awaitable), void()>(
        [this, executor](auto handler) {
          std::unique_lock<std::mutex> state(_state);
          if (!_locked) {
            _locked = true;
            state.unlock();
            _resume(executor, std::move(handler));
            return;
          }
          _waiters.push_back(Waiter{executor, std::move(handler)});
        },
        boost::asio::use_awaitable);
    co_return Guard(this);
  }

 private:
  // The lock passes straight to the next waiter, if there is one, so it is never free for
  // a newcomer to take out of turn.
  void _unlock() {
    std::unique_lock<std::mutex> state(_state);
    if (_waiters.empty()) {
      _locked = false;
      return;
    }
    auto next = std::move(_waiters.front());
    _waiters.pop_front();
    state.unlock();
    _resume(next.executor, std::move(next.handler));
  }

  struct Waiter {
    Executor executor;
    boost::asio::any_completion_handler<void()> handler;
  };

  template <typename Handler>
  static void _resume(const Executor& executor, Handler handler) {
    boost::asio::post(executor, [handler = std::move(handler)]() mutable { std::move(handler)(); });
  }

  std::mutex _state;
  bool _locked = false;
  std::deque<Waiter> _waiters;
};

}  // namespace lugh

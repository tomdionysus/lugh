//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/async_result.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/task.h"

// For the change to callback style only, the two ways across: a coroutine not yet converted
// awaits an operation that has been (awaited), and a converted operation runs a coroutine
// not yet converted (spawned). Deleted with the last coroutine above the frozen store; the
// store's own seam (store/store_calls.h) keeps spawned until Dagda.
namespace lugh {

// The deadline a coroutine caller in transition gives the operations it awaits: local work,
// the disk and a hash at most.
inline constexpr Deadline kTransitionDeadline = std::chrono::seconds(30);

// Starts `start(executor, done)` on the coroutine's own executor and resumes the coroutine
// with what `done` is given.
template <typename T, typename Start>
Task<T> awaited(Start start) {
  auto executor = co_await boost::asio::this_coro::executor;
  co_return co_await boost::asio::async_initiate<const boost::asio::use_awaitable_t<>, void(T)>(
      [executor, start = std::move(start)](auto handler) mutable {
        auto held = std::make_shared<decltype(handler)>(std::move(handler));
        start(executor, Done<T>([held](T value) { std::move (*held)(std::move(value)); }));
      },
      boost::asio::use_awaitable);
}

// What a read answered, for a coroutine that cannot go on without it: a read that could not
// happen (the store failed, the deadline passed) throws, as the stack's error rule says,
// and the router answers 500.
template <typename T, typename Start>
Task<T> awaited_value(Start start) {
  auto read = co_await awaited<Outcome<T>>(std::move(start));
  if (!read.ok()) throw std::runtime_error(read.message);
  co_return std::move(read.value);
}

// Runs `task` on `executor` and hands `answer` how it ended: its value, or `failed(why)` if
// it threw. `answer` runs on the executor once the coroutine has finished, never within
// this call.
template <typename T>
void spawned(Executor executor, Task<T> task, std::function<void(T)> answer, std::function<T(const std::string&)> failed) {
  boost::asio::co_spawn(executor, std::move(task), [answer = std::move(answer), failed = std::move(failed)](std::exception_ptr error, T value) {
    if (!error) return answer(std::move(value));
    try {
      std::rethrow_exception(error);
    } catch (const std::exception& e) {
      answer(failed(e.what()));
    } catch (...) {
      answer(failed("an unknown failure"));
    }
  });
}

}  // namespace lugh

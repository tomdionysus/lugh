//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/async_result.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <chrono>
#include <memory>
#include <utility>

#include "lugh/core/completion.h"
#include "lugh/core/task.h"

// For the change to callback style only: a coroutine not yet converted awaits an operation
// that has been. Deleted with the last coroutine caller above the frozen store.
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

}  // namespace lugh

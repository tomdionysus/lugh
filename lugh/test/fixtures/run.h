//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <optional>
#include <stdexcept>

#include "lugh/core/completion.h"
#include "lugh/core/task.h"

// Runs a coroutine to its end on an io_context of its own and answers what it answered:
// how a test, which is not a coroutine, calls one. Work it hands to another pool comes
// back here to finish.
template <typename T>
T run(lugh::Task<T> task) {
  boost::asio::io_context io;
  auto future = boost::asio::co_spawn(io, std::move(task), boost::asio::use_future);
  io.run();
  return future.get();
}

inline void run(lugh::Task<void> task) {
  boost::asio::io_context io;
  auto future = boost::asio::co_spawn(io, std::move(task), boost::asio::use_future);
  io.run();
  future.get();
}

// Starts a callback-style operation, `start(executor, done)`, on an io_context of its own,
// runs it to its answer and answers that: how a test calls one.
template <typename T, typename Start>
T wait_for(Start start) {
  boost::asio::io_context io;
  std::optional<T> out;
  start(io.get_executor(), lugh::Done<T>([&out](T value) { out = std::move(value); }));
  io.run();
  if (!out) throw std::logic_error("the operation never answered");
  return std::move(*out);
}

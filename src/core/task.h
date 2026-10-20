#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <type_traits>
#include <utility>

namespace lugh {

// What every operation that may wait answers: a C++20 coroutine on Boost.Asio. Nothing in
// Lugh waits on the disk, a hash or the network on a thread that serves anything else;
// it suspends, and resumes on its own executor when the answer is in.
template <typename T = void>
using Task = boost::asio::awaitable<T>;

using Executor = boost::asio::any_io_executor;

// Runs `work`, which blocks (a system call on a file, Argon2id), on `where`, a pool kept for
// such work, and resumes the caller on its own executor with the answer. The caller holds
// no thread while it waits.
template <typename Work>
auto offload(Executor where, Work work) -> Task<std::invoke_result_t<Work&>> {
  using Answer = std::invoke_result_t<Work&>;
  if constexpr (std::is_void_v<Answer>) {
    co_await boost::asio::co_spawn(
        where,
        [work = std::move(work)]() mutable -> Task<void> {
          work();
          co_return;
        },
        boost::asio::use_awaitable);
  } else {
    co_return co_await boost::asio::co_spawn(where, [work = std::move(work)]() mutable -> Task<Answer> { co_return work(); }, boost::asio::use_awaitable);
  }
}

}  // namespace lugh

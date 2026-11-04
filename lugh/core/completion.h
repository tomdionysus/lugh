//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <atomic>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <utility>

// Lugh's asynchronous operations take Dannan's shape (the maintainer: "Lugh goes callback style"):
// the operation's arguments, then a deadline, the caller's executor and `done`. `done` is
// posted to that executor exactly once, with the answer, or with what the operation says
// when the deadline passes first; never called inline, even when the answer is already
// known. The operation itself waits on nothing.
namespace lugh {

using Executor = boost::asio::any_io_executor;

// How long an operation may take before its caller is answered without it.
using Deadline = std::chrono::milliseconds;

template <typename T>
using Done = std::function<void(T)>;

// The one answer an operation owes its caller. finish() posts the answer to the caller's
// executor; if the deadline passes first, the caller gets late() instead, and a finish()
// after that is dropped. Whichever comes first wins, once, on any thread.
template <typename T>
class Completion : public std::enable_shared_from_this<Completion<T>> {
 public:
  // `late` says what the caller is told when the deadline passes: for a write that may
  // still land, that it may.
  static std::shared_ptr<Completion> start(Deadline deadline, Executor executor, Done<T> done, std::function<T()> late) {
    std::shared_ptr<Completion> completion(new Completion(std::move(executor), std::move(done), std::move(late)));
    completion->_timer.expires_after(deadline);
    completion->_timer.async_wait([weak = std::weak_ptr<Completion>(completion)](const boost::system::error_code& ec) {
      if (ec) return;
      if (const auto self = weak.lock()) self->_answer(self->_late());
    });
    return completion;
  }

  void finish(T value) { _answer(std::move(value)); }

  // Whether the caller has had its answer, from finish() or the deadline: work still to
  // start may be skipped.
  bool answered() const { return _answered.load(); }

 private:
  Completion(Executor executor, Done<T> done, std::function<T()> late)
      : _executor(std::move(executor)), _timer(_executor), _done(std::move(done)), _late(std::move(late)) {}

  void _answer(T value) {
    if (_answered.exchange(true)) return;
    boost::asio::post(_executor, [done = std::move(_done), value = std::move(value)]() mutable { done(std::move(value)); });
    // Cancelled from the timer's own executor, never this thread, so a deadline and an
    // answer on two threads do not touch the timer at once.
    boost::asio::post(_timer.get_executor(), [self = this->shared_from_this()] { self->_timer.cancel(); });
  }

  Executor _executor;
  boost::asio::steady_timer _timer;
  Done<T> _done;
  std::function<T()> _late;
  std::atomic<bool> _answered{false};
};

// Posts `value` to `done` on `executor`: an answer known at once still never arrives inline.
template <typename T>
void answer_now(const Executor& executor, Done<T> done, T value) {
  boost::asio::post(executor, [done = std::move(done), value = std::move(value)]() mutable { done(std::move(value)); });
}

}  // namespace lugh

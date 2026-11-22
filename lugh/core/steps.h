//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/post.hpp>
#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"

// What every callback-style operation in Lugh is built from: its one answer, and steps that
// start one another.
namespace lugh {

// An operation's answer, Outcome-shaped: `timed_out` with `late` when the deadline passes.
template <typename T>
std::shared_ptr<Completion<Outcome<T>>> answering(Deadline deadline, Executor executor, Done<Outcome<T>> done, const char* late) {
  return Completion<Outcome<T>>::start(deadline, std::move(executor), std::move(done), [late] { return Outcome<T>::failure(Fault::timed_out, late); });
}

// A step's refusal, answered as the operation's own type.
template <typename T>
Done<Outcome<Nothing>> refusing(std::shared_ptr<Completion<Outcome<T>>> answer) {
  return [answer](Outcome<Nothing> refused) { answer->finish(Outcome<T>::from(refused)); };
}

// `step` on each item in turn, each given what to call when it is done; then `then`.
template <typename Item>
void in_turn(std::shared_ptr<std::vector<Item>> items, std::size_t at, std::function<void(const Item&, std::function<void()>)> step,
             std::function<void()> then) {
  if (at >= items->size()) return then();
  const auto& item = (*items)[at];
  step(item, [items, at, step, then] { in_turn<Item>(items, at + 1, step, then); });
}

// `work`, which blocks (a hash, a system call), on `pool`, kept for such work, and what it
// answered to `answer` on `back`. `work` may hold what cannot be copied, a Secret.
template <typename Work, typename Answer>
void on_pool(Executor pool, Work work, Executor back, Answer answer) {
  boost::asio::post(pool, [work = std::move(work), back = std::move(back), answer = std::move(answer)]() mutable {
    auto value = work();
    boost::asio::post(back, [answer = std::move(answer), value = std::move(value)]() mutable { answer(std::move(value)); });
  });
}

}  // namespace lugh

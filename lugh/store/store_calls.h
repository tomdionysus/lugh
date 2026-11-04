//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/co_spawn.hpp>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "lugh/core/awaited.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/task.h"
#include "lugh/store/store.h"

// The store's operations in Dannan's shape, for the layers above it. The store underneath
// is frozen until Dagda carries Lugh's spaces and stays a coroutine; this is the one seam
// between the two styles, and goes with it.
namespace lugh::store {

namespace detail {

// The coroutines each call runs. Their arguments are parameters, copied into the frame, not
// a lambda's captures, which would be gone once the lambda was.
inline Task<Outcome<std::optional<Record>>> get_of(std::shared_ptr<const Store> store, std::string table, std::string key) {
  co_return Outcome<std::optional<Record>>::success(co_await store->get(std::move(table), std::move(key)));
}
inline Task<Outcome<std::optional<Record>>> find_of(std::shared_ptr<const Store> store, std::string table, std::string index, std::string value) {
  co_return Outcome<std::optional<Record>>::success(co_await store->find(std::move(table), std::move(index), std::move(value)));
}
inline Task<Outcome<std::vector<Record>>> list_of(std::shared_ptr<const Store> store, std::string table) {
  co_return Outcome<std::vector<Record>>::success(co_await store->list(std::move(table)));
}
inline Task<Outcome<bool>> removed_of(std::shared_ptr<const Store> store, std::string table, std::string key) {
  co_return Outcome<bool>::success(co_await store->removed(std::move(table), std::move(key)));
}
inline Task<Write> put_of(std::shared_ptr<Store> store, std::string table, std::string key, SecureBuffer value, std::optional<std::uint64_t> expected) {
  co_return co_await store->put(std::move(table), std::move(key), std::move(value), expected);
}
inline Task<Write> remove_of(std::shared_ptr<Store> store, std::string table, std::string key, std::optional<std::uint64_t> expected) {
  co_return co_await store->remove(std::move(table), std::move(key), expected);
}

template <typename T>
using Failed = std::function<T(const std::string& why)>;

// Runs `task` and hands `answer` how it ended: its value, or, if it threw, `failed`.
template <typename T>
void settle(Executor executor, Task<T> task, std::function<void(T)> answer, Failed<T> failed) {
  spawned<T>(std::move(executor), std::move(task), std::move(answer), std::move(failed));
}

// `task`'s answer to `done`, or `failed(late)` if the deadline passes first.
template <typename T>
void within(Deadline deadline, Executor executor, Done<T> done, Failed<T> failed, std::string late, Task<T> task) {
  auto completion = Completion<T>::start(deadline, executor, std::move(done), [failed, late] { return failed(late); });
  settle<T>(executor, std::move(task), [completion](T value) { completion->finish(std::move(value)); }, failed);
}

template <typename T>
Failed<Outcome<T>> read_failed() {
  return [](const std::string& why) { return Outcome<T>::failure(Fault::failed, "the store: " + why); };
}

inline Failed<Write> write_failed() {
  return [](const std::string& why) { return Write::failure(StoreError::failed, "the store: " + why); };
}

inline constexpr const char* kReadLate = "no answer within the deadline";
inline constexpr const char* kWriteLate = "no answer within the deadline; the write may yet land";

}  // namespace detail

// A read answers the record, or nothing for one that is absent; it answers `failed`, never
// nothing, when the store throws or the deadline passes, so a timeout is never taken for
// absence. A write answers the store's `Write`, `failed` when the deadline passes first,
// saying the write may yet land. Safe from any number of threads.
class StoreCalls {
 public:
  explicit StoreCalls(std::shared_ptr<Store> store) : _store(std::move(store)) {}

  void get(std::string table, std::string key, Deadline deadline, Executor executor, Done<Outcome<std::optional<Record>>> done) const {
    detail::within<Outcome<std::optional<Record>>>(deadline, executor, std::move(done), detail::read_failed<std::optional<Record>>(), detail::kReadLate,
                                                   detail::get_of(_store, std::move(table), std::move(key)));
  }

  void find(std::string table, std::string index, std::string value, Deadline deadline, Executor executor, Done<Outcome<std::optional<Record>>> done) const {
    detail::within<Outcome<std::optional<Record>>>(deadline, executor, std::move(done), detail::read_failed<std::optional<Record>>(), detail::kReadLate,
                                                   detail::find_of(_store, std::move(table), std::move(index), std::move(value)));
  }

  void list(std::string table, Deadline deadline, Executor executor, Done<Outcome<std::vector<Record>>> done) const {
    detail::within<Outcome<std::vector<Record>>>(deadline, executor, std::move(done), detail::read_failed<std::vector<Record>>(), detail::kReadLate,
                                                 detail::list_of(_store, std::move(table)));
  }

  void removed(std::string table, std::string key, Deadline deadline, Executor executor, Done<Outcome<bool>> done) const {
    detail::within<Outcome<bool>>(deadline, executor, std::move(done), detail::read_failed<bool>(), detail::kReadLate,
                                  detail::removed_of(_store, std::move(table), std::move(key)));
  }

  void put(std::string table, std::string key, SecureBuffer value, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
           Done<Write> done) {
    detail::within<Write>(deadline, executor, std::move(done), detail::write_failed(), detail::kWriteLate,
                          detail::put_of(_store, std::move(table), std::move(key), std::move(value), expected));
  }

  void remove(std::string table, std::string key, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor, Done<Write> done) {
    detail::within<Write>(deadline, executor, std::move(done), detail::write_failed(), detail::kWriteLate,
                          detail::remove_of(_store, std::move(table), std::move(key), expected));
  }

  // A read in this shape without a deadline of its own, for an operation that keeps one
  // deadline over many reads (its own Completion) and must hear each read's real answer.
  void get_settled(std::string table, std::string key, Executor executor, Done<Outcome<std::optional<Record>>> done) const {
    detail::settle<Outcome<std::optional<Record>>>(executor, detail::get_of(_store, std::move(table), std::move(key)), std::move(done),
                                                   detail::read_failed<std::optional<Record>>());
  }

  void list_settled(std::string table, Executor executor, Done<Outcome<std::vector<Record>>> done) const {
    detail::settle<Outcome<std::vector<Record>>>(executor, detail::list_of(_store, std::move(table)), std::move(done),
                                                 detail::read_failed<std::vector<Record>>());
  }

  void find_settled(std::string table, std::string index, std::string value, Executor executor, Done<Outcome<std::optional<Record>>> done) const {
    detail::settle<Outcome<std::optional<Record>>>(executor, detail::find_of(_store, std::move(table), std::move(index), std::move(value)), std::move(done),
                                                   detail::read_failed<std::optional<Record>>());
  }

  void remove_settled(std::string table, std::string key, std::optional<std::uint64_t> expected, Executor executor, Done<Write> done) {
    detail::settle<Write>(executor, detail::remove_of(_store, std::move(table), std::move(key), expected), std::move(done), detail::write_failed());
  }

  // The write's own answer, however long the disk takes, for a caller that must know how one
  // write ended before it starts the next (the audit chain's numbering). The caller's own
  // deadline is kept by its Completion, not here.
  void put_settled(std::string table, std::string key, SecureBuffer value, std::optional<std::uint64_t> expected, Executor executor, Done<Write> done) {
    detail::settle<Write>(executor, detail::put_of(_store, std::move(table), std::move(key), std::move(value), expected), std::move(done),
                          detail::write_failed());
  }

 private:
  std::shared_ptr<Store> _store;
};

}  // namespace lugh::store

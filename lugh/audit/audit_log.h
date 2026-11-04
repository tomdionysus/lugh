//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "dannan/identity/crypto.h"
#include "dannan/status/log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/status.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::audit {

// What a person or a program did. Never a secret: a refusal says that a password was
// wrong, not what was typed.
struct Event {
  // Dotted, from a fixed set: "user.create", "signin.password.refused".
  std::string action;
  // Who did it: a user ID, "system", or "anonymous" before anyone is known.
  std::string actor;
  // What it was done to: a user ID, a group ID, a factor.
  std::string subject;
  // The client address, where there is one.
  std::string source;
  // For a person reading the log.
  std::string detail;
};

// Who is acting, for the entries their changes make.
struct Actor {
  // A user ID, "system", or "anonymous".
  std::string id;
  std::string source;
};

using Hash = std::array<unsigned char, 32>;

struct Entry {
  std::uint64_t sequence = 0;
  // Seconds since the epoch.
  std::uint64_t time = 0;
  Event event;
  // The hash of the entry before; zeros before the first.
  Hash previous{};
  Hash hash{};
};

// The record of everything that matters, in the `audit` table: one record per entry, keyed
// by its sequence number, each carrying the hash of the one before. The table's seal
// already stops an edit at rest; the chain is what lets an export, or a later node, show
// that nothing was taken out of the middle or rewritten with the keys in hand.
//
// One chain per node for now. P8 gives each node its own sequence, so two nodes appending
// at once do not contend for one number.
//
// Every operation takes Dannan's shape: its deadline, the caller's executor, and `done`,
// posted there once. Safe from any number of threads.
class AuditLog : public std::enable_shared_from_this<AuditLog> {
 public:
  static constexpr const char* kTable = "audit";

  // The longest each field is kept: an entry is cut to fit, never refused, because an
  // action that happened is recorded whatever its detail says.
  static constexpr std::size_t kMostFieldBytes = 255;
  static constexpr std::size_t kMostDetailBytes = 1024;

  // Reads the tail of the chain, to carry on from it.
  static void open(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
                   Deadline deadline, Executor executor, Done<Result<std::shared_ptr<AuditLog>>> done);

  // Appends one entry. A failure is logged here as well as answered: the caller has
  // usually already done what it is recording, and cannot undo it. Entries are appended
  // one at a time, in the order asked, from a queue: each is numbered only once the one
  // before has been written or refused, so the chain has no gaps and no forks. Past the
  // deadline the caller is told the entry may yet be recorded, and it still takes its turn.
  void record(Event event, Deadline deadline, Executor executor, Done<Status> done);

  // Up to `most` entries from `from` on, in order; fewer where the chain ends. `failed` when
  // the store fails or the deadline passes, never a short page.
  void entries(std::uint64_t from, std::size_t most, Deadline deadline, Executor executor, Done<Outcome<std::vector<Entry>>> done) const;

  // The number of entries.
  std::uint64_t size() const;

  // Walks the whole chain, recomputing every hash. The number of entries, or where it
  // breaks, or that the walk did not finish within the deadline.
  void verify(Deadline deadline, Executor executor, Done<Result<std::uint64_t>> done) const;

  // The record's value, and back. Public for the tests and the fuzz target.
  static Bytes encode(const Entry& entry);
  static std::optional<Entry> decode(std::span<const unsigned char> value);
  static std::string key(std::uint64_t sequence);

 private:
  AuditLog(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall);

  // An entry asked for and not yet written.
  struct Pending {
    Event event;
    std::shared_ptr<Completion<Status>> completion;
    Executor executor;
  };
  // A walk along the chain, entries() or verify(): where it is and what it has found.
  struct Walk;

  // Writes the entry at the head of the queue, then the next, until it is empty.
  void _append_next();
  void _walk_entries(std::shared_ptr<Walk> walk) const;
  void _walk_verify(std::shared_ptr<Walk> walk) const;

  dannan::status::ScopedLogger _logger;
  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;

  // Guards the chain's tail and the queue. Held for moments only: never across a write.
  mutable dannan::contract::Mutex _mutex;
  std::uint64_t _next DANNAN_GUARDED_BY(_mutex) = 1;
  Hash _last DANNAN_GUARDED_BY(_mutex){};
  std::deque<Pending> _queue DANNAN_GUARDED_BY(_mutex);
  // Whether an entry is being written: the queue's one in flight.
  bool _appending DANNAN_GUARDED_BY(_mutex) = false;
};

}  // namespace lugh::audit

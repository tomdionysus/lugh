//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/async_mutex.h"
#include "core/status.h"
#include "core/task.h"
#include "crypto/digest.h"
#include "loggers/logger.h"
#include "store/store.h"
#include "system/clock.h"

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

using Hash = std::array<unsigned char, crypto::kSha256Bytes>;

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
class AuditLog {
 public:
  static constexpr const char* kTable = "audit";

  // The longest each field is kept: an entry is cut to fit, never refused, because an
  // action that happened is recorded whatever its detail says.
  static constexpr std::size_t kMostFieldBytes = 255;
  static constexpr std::size_t kMostDetailBytes = 1024;

  // Reads the tail of the chain, to carry on from it.
  static Task<Result<std::shared_ptr<AuditLog>>> open(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store,
                                                      std::shared_ptr<system::Clock> clock);

  // Appends one entry. A failure is logged here as well as answered: the caller has
  // usually already done what it is recording, and cannot undo it. Entries are appended
  // one at a time, each waiting its turn without holding a thread.
  Task<Status> record(Event event);

  // Up to `most` entries from `from` on, in order.
  Task<std::vector<Entry>> entries(std::uint64_t from, std::size_t most) const;

  // The number of entries.
  std::uint64_t size() const;

  // Walks the whole chain, recomputing every hash. The number of entries, or where it
  // breaks.
  Task<Result<std::uint64_t>> verify() const;

  // The record's value, and back. Public for the tests and the fuzz target.
  static Bytes encode(const Entry& entry);
  static std::optional<Entry> decode(std::span<const unsigned char> value);
  static std::string key(std::uint64_t sequence);

 private:
  AuditLog(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store, std::shared_ptr<system::Clock> clock);

  std::shared_ptr<loggers::Logger> _logger;
  std::shared_ptr<store::Store> _store;
  std::shared_ptr<system::Clock> _clock;

  // Held from taking a sequence number to its record being written, so the chain has no
  // gaps and no forks.
  AsyncMutex _appending;
  // Guards the two below for size(), which does not wait.
  mutable std::mutex _mutex;
  std::uint64_t _next = 1;
  Hash _last{};
};

}  // namespace lugh::audit

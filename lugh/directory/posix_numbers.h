//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <memory>

#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::directory {

// uidNumber and gidNumber (TODO/2026-11-04-ldap.md, "POSIX numbers"): each range a counter in the
// `counters` table, advanced by compare-and-set against its version, so two creations cannot share
// a number and one given out is never given again, whatever becomes of who had it. On P8 each node
// leases a block from the counter instead. Safe from any number of threads; made with
// std::make_shared.
class PosixNumbers : public std::enable_shared_from_this<PosixNumbers> {
 public:
  static constexpr const char* kTable = "counters";

  struct Range {
    std::uint32_t first = 0;
    std::uint32_t last = 0;
  };

  PosixNumbers(std::shared_ptr<store::Store> store, Range users, Range groups);

  // The next number; refused once the range is used up.
  void next_user(Executor executor, Done<Outcome<std::uint32_t>> done);
  void next_group(Executor executor, Done<Outcome<std::uint32_t>> done);

 private:
  void _next(std::string key, Range range, int tries, Executor executor, Done<Outcome<std::uint32_t>> done);

  store::StoreCalls _calls;
  Range _users;
  Range _groups;
};

}  // namespace lugh::directory

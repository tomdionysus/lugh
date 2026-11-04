//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secure_bytes.h"
#include "lugh/directory/directory.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::scopes {

// The scopes one group grants its members, and the version of that record, for the API's
// ETags: zero when the group has never been granted anything.
struct Granted {
  std::vector<std::string> scopes;
  std::uint64_t version = 0;
};

// Which group grants which scopes, in `scope_grants`, one record per group keyed by its
// ID (TODO/2026-11-04-oauth.md, "Grants: groups hold scopes"). A principal's effective
// scopes are the union over its groups, read when they are needed, so taking someone out
// of a group takes effect at the next read. There is no grant to a person alone: a group
// of one does that. A cleared set is written empty, never removed, since a removal is
// final and the group may be granted again; a removed group's record is left, unread,
// since nobody is in it and its ID is never used again.
//
// Every operation takes Dannan's shape (core/completion.h). Made with std::make_shared.
class Grants : public std::enable_shared_from_this<Grants> {
 public:
  static constexpr const char* kTable = "scope_grants";
  // A group grants at most this many.
  static constexpr std::size_t kMostScopes = 256;

  Grants(std::shared_ptr<store::Store> store, std::shared_ptr<directory::Directory> directory, std::shared_ptr<audit::AuditLog> audit);

  // not_found when there is no such group.
  void group(std::string group_id, Deadline deadline, Executor executor, Done<Outcome<Granted>> done) const;

  // Replaces the group's set with `scopes`, each checked by grantable(), sorted and each
  // once. `expected` is the version last read (zero for a group never granted anything);
  // conflict when it is not current; without one, made against the version just read.
  void group_set(audit::Actor actor, std::string group_id, std::vector<std::string> scopes, std::optional<std::uint64_t> expected, Deadline deadline,
                 Executor executor, Done<Outcome<Granted>> done);

  // Every scope the user's groups grant, sorted, each once. Empty for a user in no group,
  // or one who does not exist.
  void effective(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const;

  static SecureBuffer encode(const std::vector<std::string>& scopes);
  static std::optional<std::vector<std::string>> decode(std::span<const unsigned char> value);

 private:
  void _read(std::string group_id, Executor executor, Done<Outcome<Granted>> done) const;

  store::StoreCalls _calls;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::scopes

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
#include <string>
#include <vector>

#include "lugh/audit/audit_log.h"
#include "lugh/core/outcome.h"
#include "lugh/core/task.h"
#include "lugh/directory/records.h"
#include "lugh/loggers/logger.h"
#include "lugh/store/store.h"
#include "lugh/system/clock.h"
#include "lugh/system/random.h"

namespace lugh::directory {

// Something else that keeps records about a user (the password, the factors), told when
// the user is removed so nothing of theirs is left behind.
class Dependent {
 public:
  virtual ~Dependent() = default;
  virtual Task<Status> forget(audit::Actor actor, std::string user_id) = 0;
};

struct NewUser {
  Kind kind = Kind::person;
  std::string name;
  std::string email;
  std::string display_name;
};

// What to change; what is absent stays as it is.
struct UserChange {
  std::optional<std::string> name;
  std::optional<std::string> email;
  std::optional<std::string> display_name;
};

struct GroupChange {
  std::optional<std::string> name;
  std::optional<std::string> description;
};

// Users, groups and who is in which, over the store, with every change audited. Names and
// addresses are checked and folded here, so the store holds them one way only. A write
// takes the version the caller last saw, for the API's ETags; without one it is made
// against the version just read, so two writers never silently overwrite each other.
//
// Every operation is a coroutine over the store and the audit log, and holds no thread
// while either works. Arguments are owned.
class Directory {
 public:
  Directory(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store, std::shared_ptr<system::Random> random,
            std::shared_ptr<system::Clock> clock, std::shared_ptr<audit::AuditLog> audit);

  // Told, in the order added, when a user is removed. Set up before anything is served.
  void dependent_add(std::shared_ptr<Dependent> dependent);

  // A person starts not enrolled: they set a password and a second factor through an
  // enrolment link before anything else. A service is enrolled at once, having neither.
  Task<Outcome<User>> create_user(audit::Actor actor, NewUser user);

  Task<std::optional<User>> user(std::string id) const;
  Task<std::optional<User>> user_by_name(std::string name) const;
  Task<std::optional<User>> user_by_email(std::string email) const;
  // A name, or an address if it has an '@'.
  Task<std::optional<User>> user_by_login(std::string login) const;
  Task<std::vector<User>> users() const;

  Task<Outcome<User>> update_user(audit::Actor actor, std::string id, UserChange change, std::optional<std::uint64_t> expected = std::nullopt);
  Task<Outcome<User>> disable_user(audit::Actor actor, std::string id, bool disabled, std::optional<std::uint64_t> expected = std::nullopt);
  // For authn: set once enrolment finishes, cleared when an administrator resets factors.
  Task<Outcome<User>> enrolled_set(audit::Actor actor, std::string id, bool enrolled);

  // The user, their memberships, and what each dependent keeps. Final: the ID is never
  // used again, though the name and address are free for someone new.
  Task<Outcome<>> remove_user(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected = std::nullopt);

  Task<Outcome<Group>> create_group(audit::Actor actor, std::string name, std::string description);
  Task<std::optional<Group>> group(std::string id) const;
  Task<std::optional<Group>> group_by_name(std::string name) const;
  Task<std::vector<Group>> groups() const;
  Task<Outcome<Group>> update_group(audit::Actor actor, std::string id, GroupChange change, std::optional<std::uint64_t> expected = std::nullopt);
  Task<Outcome<>> remove_group(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected = std::nullopt);

  // Adding someone already in the group is a success that changes nothing.
  Task<Outcome<>> add_member(audit::Actor actor, std::string group_id, std::string user_id);
  Task<Outcome<>> remove_member(audit::Actor actor, std::string group_id, std::string user_id);
  // User IDs, and group IDs, in order, each once.
  Task<std::vector<std::string>> members(std::string group_id) const;
  Task<std::vector<std::string>> groups_of(std::string user_id) const;

 private:
  std::optional<std::string> _new_id();
  Task<std::vector<Membership>> _memberships() const;
  Task<Outcome<User>> _put_user(audit::Actor actor, User user, std::uint64_t expected, std::string action, std::string detail);
  Task<Outcome<Group>> _put_group(audit::Actor actor, Group group, std::uint64_t expected, std::string action);
  Task<void> _audit(const audit::Actor& actor, std::string action, std::string subject, std::string detail = {});

  std::shared_ptr<loggers::Logger> _logger;
  std::shared_ptr<store::Store> _store;
  std::shared_ptr<system::Random> _random;
  std::shared_ptr<system::Clock> _clock;
  std::shared_ptr<audit::AuditLog> _audit_log;
  std::vector<std::shared_ptr<Dependent>> _dependents;
};

// The store's refusal, as the directory says it.
Fault fault_of(store::StoreError error);

}  // namespace lugh::directory

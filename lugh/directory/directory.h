//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dannan/contract/time_source.h"
#include "dannan/status/log.h"
#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/status.h"
#include "lugh/core/task.h"
#include "lugh/directory/posix_numbers.h"
#include "lugh/directory/records.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::directory {

// Something else that keeps records about a user (the password, the factors), told when
// the user is removed so nothing of theirs is left behind.
class Dependent {
 public:
  virtual ~Dependent() = default;
  // Everything kept for the user, removed; in Dannan's shape.
  virtual void forget(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Status> done) = 0;
};

struct NewUser {
  Kind kind = Kind::person;
  std::string name;
  std::string email;
  std::string display_name;
  std::string given_name;
  std::string family_name;
};

// What to change; what is absent stays as it is.
struct UserChange {
  std::optional<std::string> name;
  std::optional<std::string> email;
  std::optional<std::string> display_name;
  std::optional<std::string> given_name;
  std::optional<std::string> family_name;
};

struct GroupChange {
  std::optional<std::string> name;
  std::optional<std::string> description;
};

// What a backfill numbered.
struct Numbered {
  std::size_t users = 0;
  std::size_t groups = 0;
};

// Users, groups and who is in which, over the store, with every change audited. Names and
// addresses are checked and folded here, so the store holds them one way only. A write
// takes the version the caller last saw, for the API's ETags; without one it is made
// against the version just read, so two writers never silently overwrite each other.
//
// Every operation takes Dannan's shape: its arguments, a deadline, the caller's executor
// and `done`, posted there once. A read answers what it found, nothing for what is absent,
// or `failed` when the store fails or the deadline passes, never nothing in its place. A
// change past its deadline is answered `failed`, saying it may yet be made. Safe from any
// number of threads; made with std::make_shared.
class Directory : public std::enable_shared_from_this<Directory> {
 public:
  Directory(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
            std::shared_ptr<audit::AuditLog> audit);

  // Told, in the order added, when a user is removed. Set up before anything is served. Held
  // weakly: whoever made it keeps it, and a dependent such as AppPasswords holds this directory,
  // so a strong hold here would keep both alive for ever (LeakSanitizer, 2026-11-14).
  void dependent_add(const std::shared_ptr<Dependent>& dependent);

  // Where POSIX numbers come from, if they are configured: a person or a group gets one when made.
  // Set up before anything is served.
  void numbers_set(std::shared_ptr<PosixNumbers> numbers);

  // Every person and group without a number given one, in creation order, in one audited pass.
  // refused when none are configured. Past its deadline, those done stay done, and running it again
  // finishes the rest.
  void allocate_numbers(audit::Actor actor, Deadline deadline, Executor executor, Done<Outcome<Numbered>> done);

  // A person starts not enrolled: they set a password and a second factor through an
  // enrolment link before anything else. A service is enrolled at once, having neither.
  void create_user(audit::Actor actor, NewUser user, Deadline deadline, Executor executor, Done<Outcome<User>> done);

  void user(std::string id, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const;
  void user_by_name(std::string name, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const;
  void user_by_email(std::string email, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const;
  // A name, or an address if it has an '@'.
  void user_by_login(std::string login, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const;
  void users(Deadline deadline, Executor executor, Done<Outcome<std::vector<User>>> done) const;

  void update_user(audit::Actor actor, std::string id, UserChange change, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                   Done<Outcome<User>> done);
  void disable_user(audit::Actor actor, std::string id, bool disabled, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                    Done<Outcome<User>> done);
  // For authn: set once enrolment finishes, cleared when an administrator resets factors.
  void enrolled_set(audit::Actor actor, std::string id, bool enrolled, Deadline deadline, Executor executor, Done<Outcome<User>> done);

  // The user, their memberships, and what each dependent keeps. Final: the ID is never
  // used again, though the name and address are free for someone new.
  void remove_user(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor, Done<Outcome<>> done);

  void create_group(audit::Actor actor, std::string name, std::string description, Deadline deadline, Executor executor, Done<Outcome<Group>> done);
  void group(std::string id, Deadline deadline, Executor executor, Done<Outcome<std::optional<Group>>> done) const;
  void group_by_name(std::string name, Deadline deadline, Executor executor, Done<Outcome<std::optional<Group>>> done) const;
  void groups(Deadline deadline, Executor executor, Done<Outcome<std::vector<Group>>> done) const;
  void update_group(audit::Actor actor, std::string id, GroupChange change, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                    Done<Outcome<Group>> done);
  void remove_group(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // Adding someone already in the group is a success that changes nothing.
  void add_member(audit::Actor actor, std::string group_id, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done);
  void remove_member(audit::Actor actor, std::string group_id, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done);
  // User IDs, and group IDs, in order, each once.
  void members(std::string group_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const;
  void groups_of(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const;
  // Every membership there is, for what reads the whole directory at once.
  void memberships(Deadline deadline, Executor executor, Done<Outcome<std::vector<Membership>>> done) const;

 private:
  using Then = std::function<void()>;

  // A user's or a group's id: Dannan's RandomId, sixteen random bytes. A store record's key
  // stays its text, as P8's register map keys it.
  struct RecordIdTag {};
  static std::string _new_id();
  // The steps every operation is made of, each with the store's real answer, no deadline of
  // their own: the operation's Completion keeps that.
  void _user(std::string id, Executor executor, Done<Outcome<std::optional<User>>> done) const;
  void _group(std::string id, Executor executor, Done<Outcome<std::optional<Group>>> done) const;
  void _memberships(Executor executor, Done<Outcome<std::vector<Membership>>> done) const;
  // `then` if no live record has `value` in `index`; otherwise `refused` with the message,
  // or the store's failure. An empty value is free.
  void _free(std::string table, std::string index, std::string value, std::string taken, Executor executor, Done<Outcome<Nothing>> refused, Then then) const;
  void _put_user(audit::Actor actor, User user, std::uint64_t expected, std::string action, std::string detail, Executor executor, Done<Outcome<User>> done);
  void _put_group(audit::Actor actor, Group group, std::uint64_t expected, std::string action, Executor executor, Done<Outcome<Group>> done);
  // The memberships matching `matches` removed, one after another; their failures are
  // tidying a retry finishes, and do not stop the rest.
  void _remove_memberships(std::function<bool(const Membership&)> matches, Executor executor, Then then);
  void _audit(const audit::Actor& actor, std::string action, std::string subject, std::string detail, Executor executor, Then then);

  dannan::status::ScopedLogger _logger;
  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<audit::AuditLog> _audit_log;
  std::vector<std::weak_ptr<Dependent>> _dependents;
  std::shared_ptr<PosixNumbers> _numbers;
};

// The store's refusal, as the directory says it.
Fault fault_of(store::StoreError error);

}  // namespace lugh::directory

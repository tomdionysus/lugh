//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/directory/directory.h"

#include <set>

#include "dannan/identity/crypto.h"
#include "lugh/core/awaited.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"

namespace lugh::directory {

namespace {

constexpr std::size_t kIdBytes = 16;
constexpr const char* kNameRule = "a name is 1 to 64 letters, digits, '.', '_' or '-', starting with a letter or digit";

std::string join_change(const std::vector<std::string>& fields) {
  std::string out;
  for (const auto& field : fields) out += (out.empty() ? "" : ", ") + field;
  return out;
}

std::optional<User> user_of(const store::Record& record) {
  auto user = decode_user(record.value);
  if (!user) return std::nullopt;
  user->id = record.key;
  user->version = record.version;
  return user;
}

std::optional<Group> group_of(const store::Record& record) {
  auto group = decode_group(record.value);
  if (!group) return std::nullopt;
  group->id = record.key;
  group->version = record.version;
  return group;
}

}  // namespace

Fault fault_of(store::StoreError error) {
  switch (error) {
    case store::StoreError::none:
      return Fault::none;
    case store::StoreError::not_found:
    case store::StoreError::removed:
      return Fault::not_found;
    case store::StoreError::conflict:
      return Fault::conflict;
    case store::StoreError::duplicate:
      return Fault::duplicate;
    case store::StoreError::invalid:
      return Fault::invalid;
    case store::StoreError::failed:
      return Fault::failed;
  }
  return Fault::failed;
}

Directory::Directory(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
                     std::shared_ptr<audit::AuditLog> audit)
    : _logger(std::move(log), "directory"), _calls(std::move(store)), _wall(wall), _audit_log(std::move(audit)) {}

void Directory::dependent_add(const std::shared_ptr<Dependent>& dependent) { _dependents.push_back(dependent); }

void Directory::numbers_set(std::shared_ptr<PosixNumbers> numbers) { _numbers = std::move(numbers); }

namespace {

constexpr Deadline kBackfillDeadline = std::chrono::seconds(30);
constexpr const char* kChangeLate = "the directory did not answer within the deadline; the change may yet be made";
constexpr const char* kNamePartRule = "a given or family name is printable UTF-8, at most 128 bytes";
constexpr const char* kReadLate = "the directory was not read within the deadline";
// What the audit log is given to record a change the directory has made.
constexpr Deadline kAuditDeadline = std::chrono::seconds(30);

}  // namespace

// ---------------------------------------------------------------- users

void Directory::create_user(audit::Actor actor, NewUser fresh, Deadline deadline, Executor executor, Done<Outcome<User>> done) {
  using Answer = Outcome<User>;
  auto answer = answering<User>(deadline, executor, std::move(done), kChangeLate);
  const auto name = normal_name(fresh.name);
  if (!name) return answer->finish(Answer::failure(Fault::invalid, kNameRule));

  std::string email;
  if (!fresh.email.empty()) {
    const auto normal = normal_email(fresh.email);
    if (!normal) return answer->finish(Answer::failure(Fault::invalid, "not an email address"));
    email = *normal;
  }
  if (!printable(fresh.display_name, kMostDisplayBytes))
    return answer->finish(Answer::failure(Fault::invalid, "a display name is printable UTF-8, at most 128 bytes"));
  if (!printable(fresh.given_name, kMostDisplayBytes) || !printable(fresh.family_name, kMostDisplayBytes))
    return answer->finish(Answer::failure(Fault::invalid, kNamePartRule));

  auto self = shared_from_this();
  _free(kUsers, "name", *name, "the name " + *name + " is taken", executor, refusing(answer), [=]() mutable {
    self->_free(kUsers, "email", email, "the address " + email + " is taken", executor, refusing(answer), [=]() mutable {
      const auto id = self->_new_id();
      if (!id) return answer->finish(Answer::failure(Fault::failed, "no randomness for an ID"));
      User user;
      user.id = *id;
      user.kind = fresh.kind;
      user.enrolled = fresh.kind == Kind::service;
      user.name = *name;
      user.email = email;
      user.display_name = fresh.display_name;
      user.given_name = fresh.given_name;
      user.family_name = fresh.family_name;
      user.created = user.updated = (self->_wall.unix_ms() / 1000);
      const auto put = [=](User ready) {
        self->_put_user(actor, std::move(ready), 0, "user.create", fresh.kind == Kind::service ? "service" : "person", executor,
                        [answer](Answer made) { answer->finish(std::move(made)); });
      };
      // A service cannot have a posixAccount, so it spends no number.
      if (!self->_numbers || fresh.kind == Kind::service) return put(std::move(user));
      self->_numbers->next_user(executor, [=](Outcome<std::uint32_t> number) mutable {
        if (!number.ok()) return answer->finish(Answer::from(number));
        user.posix_number = number.value;
        put(std::move(user));
      });
    });
  });
}

void Directory::user(std::string id, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const {
  auto answer = answering<std::optional<User>>(deadline, executor, std::move(done), kReadLate);
  _user(std::move(id), executor, [answer](Outcome<std::optional<User>> found) { answer->finish(std::move(found)); });
}

void Directory::user_by_name(std::string name, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const {
  using Answer = Outcome<std::optional<User>>;
  auto answer = answering<std::optional<User>>(deadline, executor, std::move(done), kReadLate);
  const auto normal = normal_name(name);
  if (!normal) return answer->finish(Answer::success(std::nullopt));
  _calls.find_settled(kUsers, "name", *normal, executor, [answer](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    answer->finish(Answer::success(record.value ? user_of(*record.value) : std::nullopt));
  });
}

void Directory::user_by_email(std::string email, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const {
  using Answer = Outcome<std::optional<User>>;
  auto answer = answering<std::optional<User>>(deadline, executor, std::move(done), kReadLate);
  const auto normal = normal_email(email);
  if (!normal) return answer->finish(Answer::success(std::nullopt));
  _calls.find_settled(kUsers, "email", *normal, executor, [answer](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    answer->finish(Answer::success(record.value ? user_of(*record.value) : std::nullopt));
  });
}

void Directory::user_by_login(std::string login, Deadline deadline, Executor executor, Done<Outcome<std::optional<User>>> done) const {
  if (login.find('@') == std::string::npos) return user_by_name(std::move(login), deadline, std::move(executor), std::move(done));
  user_by_email(std::move(login), deadline, std::move(executor), std::move(done));
}

void Directory::users(Deadline deadline, Executor executor, Done<Outcome<std::vector<User>>> done) const {
  using Answer = Outcome<std::vector<User>>;
  auto answer = answering<std::vector<User>>(deadline, executor, std::move(done), kReadLate);
  _calls.list_settled(kUsers, executor, [answer](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    std::vector<User> out;
    for (const auto& record : records.value) {
      if (auto found = user_of(record)) out.push_back(std::move(*found));
    }
    answer->finish(Answer::success(std::move(out)));
  });
}

void Directory::update_user(audit::Actor actor, std::string id, UserChange change, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                            Done<Outcome<User>> done) {
  using Answer = Outcome<User>;
  auto answer = answering<User>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _user(id, executor, [=](Outcome<std::optional<User>> read) mutable {
    if (!read.ok()) return answer->finish(Answer::from(read));
    if (!read.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    auto found = std::make_shared<User>(std::move(*read.value));
    if (expected && *expected != found->version) return answer->finish(Answer::failure(Fault::conflict, "the user has changed since it was read"));
    const auto version = found->version;

    // Checked first, all of them, before anything is looked up.
    std::optional<std::string> name;
    if (change.name) {
      name = normal_name(*change.name);
      if (!name) return answer->finish(Answer::failure(Fault::invalid, kNameRule));
    }
    std::optional<std::string> email;
    if (change.email) {
      email = std::string();
      if (!change.email->empty()) {
        const auto normal = normal_email(*change.email);
        if (!normal) return answer->finish(Answer::failure(Fault::invalid, "not an email address"));
        email = *normal;
      }
    }
    if (change.display_name && !printable(*change.display_name, kMostDisplayBytes))
      return answer->finish(Answer::failure(Fault::invalid, "a display name is printable UTF-8, at most 128 bytes"));
    if ((change.given_name && !printable(*change.given_name, kMostDisplayBytes)) || (change.family_name && !printable(*change.family_name, kMostDisplayBytes)))
      return answer->finish(Answer::failure(Fault::invalid, kNamePartRule));

    const auto new_name = name && *name != found->name ? *name : std::string();
    const auto new_email = email && *email != found->email ? *email : std::string();
    self->_free(kUsers, "name", new_name, "the name " + new_name + " is taken", executor, refusing(answer), [=]() mutable {
      self->_free(kUsers, "email", new_email, "the address " + new_email + " is taken", executor, refusing(answer), [=]() mutable {
        std::vector<std::string> changed;
        if (name && *name != found->name) {
          changed.push_back("name " + found->name + " to " + *name);
          found->name = *name;
        }
        if (email && *email != found->email) {
          changed.push_back("email");
          found->email = *email;
        }
        if (change.display_name && *change.display_name != found->display_name) {
          changed.push_back("display name");
          found->display_name = *change.display_name;
        }
        if (change.given_name && *change.given_name != found->given_name) {
          changed.push_back("given name");
          found->given_name = *change.given_name;
        }
        if (change.family_name && *change.family_name != found->family_name) {
          changed.push_back("family name");
          found->family_name = *change.family_name;
        }
        if (changed.empty()) return answer->finish(Answer::success(std::move(*found)));
        found->updated = (self->_wall.unix_ms() / 1000);
        self->_put_user(actor, std::move(*found), version, "user.update", join_change(changed), executor,
                        [answer](Answer made) { answer->finish(std::move(made)); });
      });
    });
  });
}

void Directory::disable_user(audit::Actor actor, std::string id, bool disabled, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                             Done<Outcome<User>> done) {
  using Answer = Outcome<User>;
  auto answer = answering<User>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _user(id, executor, [=](Outcome<std::optional<User>> read) {
    if (!read.ok()) return answer->finish(Answer::from(read));
    if (!read.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    auto found = std::move(*read.value);
    if (expected && *expected != found.version) return answer->finish(Answer::failure(Fault::conflict, "the user has changed since it was read"));
    if (found.disabled == disabled) return answer->finish(Answer::success(std::move(found)));
    const auto version = found.version;
    found.disabled = disabled;
    found.updated = (self->_wall.unix_ms() / 1000);
    self->_put_user(actor, std::move(found), version, disabled ? "user.disable" : "user.enable", {}, executor,
                    [answer](Answer made) { answer->finish(std::move(made)); });
  });
}

void Directory::enrolled_set(audit::Actor actor, std::string id, bool enrolled, Deadline deadline, Executor executor, Done<Outcome<User>> done) {
  using Answer = Outcome<User>;
  auto answer = answering<User>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _user(id, executor, [=](Outcome<std::optional<User>> read) {
    if (!read.ok()) return answer->finish(Answer::from(read));
    if (!read.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    auto found = std::move(*read.value);
    if (found.enrolled == enrolled) return answer->finish(Answer::success(std::move(found)));
    const auto version = found.version;
    found.enrolled = enrolled;
    found.updated = (self->_wall.unix_ms() / 1000);
    self->_put_user(actor, std::move(found), version, enrolled ? "user.enrolled" : "user.unenrolled", {}, executor,
                    [answer](Answer made) { answer->finish(std::move(made)); });
  });
}

void Directory::remove_user(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                            Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _user(id, executor, [=](Outcome<std::optional<User>> read) {
    if (!read.ok()) return answer->finish(Answer::from(read));
    if (!read.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    const auto found = *read.value;
    if (expected && *expected != found.version) return answer->finish(Answer::failure(Fault::conflict, "the user has changed since it was read"));

    // The user record goes first and conditionally: if it fails, nothing else has been
    // touched; once it is gone, the rest is tidying that a retry can finish.
    self->_calls.remove_settled(kUsers, id, found.version, executor, [=](store::Write removed) {
      if (!removed.ok()) return answer->finish(Answer::failure(fault_of(removed.error), removed.message));
      self->_audit(actor, "user.remove", found.id, found.name, executor, [=] {
        self->_remove_memberships([id](const Membership& membership) { return membership.user_id == id; }, executor,
                                  [=] {
                                    // Those still kept by their owner; one gone has nothing left to forget.
                                    auto dependents = std::make_shared<std::vector<std::shared_ptr<Dependent>>>();
                                    for (const auto& weak : self->_dependents) {
                                      if (auto dependent = weak.lock()) dependents->push_back(std::move(dependent));
                                    }
                                    in_turn<std::shared_ptr<Dependent>>(
                                        dependents, 0,
                                        [=](const std::shared_ptr<Dependent>& dependent, std::function<void()> next) {
                                          dependent->forget(actor, found.id, kAuditDeadline, executor, [=](Status forgotten) {
                                            if (!forgotten.ok) self->_logger.error("removing user " + found.id + ": " + forgotten.error);
                                            next();
                                          });
                                        },
                                        [answer] { answer->finish(Answer::success()); });
                                  });
      });
    });
  });
}

// ---------------------------------------------------------------- groups

void Directory::create_group(audit::Actor actor, std::string name, std::string description, Deadline deadline, Executor executor, Done<Outcome<Group>> done) {
  using Answer = Outcome<Group>;
  auto answer = answering<Group>(deadline, executor, std::move(done), kChangeLate);
  const auto normal = normal_name(name);
  if (!normal) return answer->finish(Answer::failure(Fault::invalid, kNameRule));
  if (!printable(description, kMostDescriptionBytes))
    return answer->finish(Answer::failure(Fault::invalid, "a description is printable UTF-8, at most 1024 bytes"));

  auto self = shared_from_this();
  _free(kGroups, "name", *normal, "the name " + *normal + " is taken", executor, refusing(answer), [=]() mutable {
    const auto id = self->_new_id();
    if (!id) return answer->finish(Answer::failure(Fault::failed, "no randomness for an ID"));
    Group group;
    group.id = *id;
    group.name = *normal;
    group.description = description;
    group.created = group.updated = (self->_wall.unix_ms() / 1000);
    const auto put = [=](Group ready) {
      self->_put_group(actor, std::move(ready), 0, "group.create", executor, [answer](Answer made) { answer->finish(std::move(made)); });
    };
    if (!self->_numbers) return put(std::move(group));
    self->_numbers->next_group(executor, [=](Outcome<std::uint32_t> number) mutable {
      if (!number.ok()) return answer->finish(Answer::from(number));
      group.posix_number = number.value;
      put(std::move(group));
    });
  });
}

void Directory::group(std::string id, Deadline deadline, Executor executor, Done<Outcome<std::optional<Group>>> done) const {
  auto answer = answering<std::optional<Group>>(deadline, executor, std::move(done), kReadLate);
  _group(std::move(id), executor, [answer](Outcome<std::optional<Group>> found) { answer->finish(std::move(found)); });
}

void Directory::group_by_name(std::string name, Deadline deadline, Executor executor, Done<Outcome<std::optional<Group>>> done) const {
  using Answer = Outcome<std::optional<Group>>;
  auto answer = answering<std::optional<Group>>(deadline, executor, std::move(done), kReadLate);
  const auto normal = normal_name(name);
  if (!normal) return answer->finish(Answer::success(std::nullopt));
  _calls.find_settled(kGroups, "name", *normal, executor, [answer](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    answer->finish(Answer::success(record.value ? group_of(*record.value) : std::nullopt));
  });
}

void Directory::groups(Deadline deadline, Executor executor, Done<Outcome<std::vector<Group>>> done) const {
  using Answer = Outcome<std::vector<Group>>;
  auto answer = answering<std::vector<Group>>(deadline, executor, std::move(done), kReadLate);
  _calls.list_settled(kGroups, executor, [answer](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    std::vector<Group> out;
    for (const auto& record : records.value) {
      if (auto found = group_of(record)) out.push_back(std::move(*found));
    }
    answer->finish(Answer::success(std::move(out)));
  });
}

void Directory::update_group(audit::Actor actor, std::string id, GroupChange change, std::optional<std::uint64_t> expected, Deadline deadline,
                             Executor executor, Done<Outcome<Group>> done) {
  using Answer = Outcome<Group>;
  auto answer = answering<Group>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _group(id, executor, [=](Outcome<std::optional<Group>> read) mutable {
    if (!read.ok()) return answer->finish(Answer::from(read));
    if (!read.value) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
    auto found = std::make_shared<Group>(std::move(*read.value));
    if (expected && *expected != found->version) return answer->finish(Answer::failure(Fault::conflict, "the group has changed since it was read"));
    const auto version = found->version;

    std::optional<std::string> name;
    if (change.name) {
      name = normal_name(*change.name);
      if (!name) return answer->finish(Answer::failure(Fault::invalid, kNameRule));
    }
    if (change.description && !printable(*change.description, kMostDescriptionBytes))
      return answer->finish(Answer::failure(Fault::invalid, "a description is printable UTF-8, at most 1024 bytes"));

    const auto new_name = name && *name != found->name ? *name : std::string();
    self->_free(kGroups, "name", new_name, "the name " + new_name + " is taken", executor, refusing(answer), [=]() mutable {
      bool changed = false;
      if (name && *name != found->name) {
        found->name = *name;
        changed = true;
      }
      if (change.description && *change.description != found->description) {
        found->description = *change.description;
        changed = true;
      }
      if (!changed) return answer->finish(Answer::success(std::move(*found)));
      found->updated = (self->_wall.unix_ms() / 1000);
      self->_put_group(actor, std::move(*found), version, "group.update", executor, [answer](Answer made) { answer->finish(std::move(made)); });
    });
  });
}

void Directory::remove_group(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                             Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _group(id, executor, [=](Outcome<std::optional<Group>> read) {
    if (!read.ok()) return answer->finish(Answer::from(read));
    if (!read.value) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
    const auto found = *read.value;
    if (expected && *expected != found.version) return answer->finish(Answer::failure(Fault::conflict, "the group has changed since it was read"));

    self->_calls.remove_settled(kGroups, id, found.version, executor, [=](store::Write removed) {
      if (!removed.ok()) return answer->finish(Answer::failure(fault_of(removed.error), removed.message));
      self->_audit(actor, "group.remove", found.id, found.name, executor, [=] {
        self->_remove_memberships([id](const Membership& membership) { return membership.group_id == id; }, executor,
                                  [answer] { answer->finish(Answer::success()); });
      });
    });
  });
}

// ---------------------------------------------------------------- memberships

void Directory::add_member(audit::Actor actor, std::string group_id, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _group(group_id, executor, [=](Outcome<std::optional<Group>> group) {
    if (!group.ok()) return answer->finish(Answer::from(group));
    if (!group.value) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
    self->_user(user_id, executor, [=](Outcome<std::optional<User>> user) {
      if (!user.ok()) return answer->finish(Answer::from(user));
      if (!user.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
      self->_memberships(executor, [=](Outcome<std::vector<Membership>> memberships) {
        if (!memberships.ok()) return answer->finish(Answer::from(memberships));
        for (const auto& membership : memberships.value) {
          if (membership.group_id == group_id && membership.user_id == user_id) return answer->finish(Answer::success());
        }

        const auto instance = dannan::identity::random_bytes(8);
        Membership membership;
        membership.group_id = group_id;
        membership.user_id = user_id;
        membership.added = (self->_wall.unix_ms() / 1000);
        const auto key = membership.group_id + "/" + membership.user_id + "/" + dannan::identity::hex(instance);
        self->_calls.put_settled(kMemberships, key, encode(membership), 0, executor, [=](store::Write written) {
          if (!written.ok()) return answer->finish(Answer::failure(fault_of(written.error), written.message));
          self->_audit(actor, "group.member.add", group_id, "user " + user_id, executor, [answer] { answer->finish(Answer::success()); });
        });
      });
    });
  });
}

void Directory::remove_member(audit::Actor actor, std::string group_id, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _memberships(executor, [=](Outcome<std::vector<Membership>> memberships) {
    if (!memberships.ok()) return answer->finish(Answer::from(memberships));
    auto matching = std::make_shared<std::vector<Membership>>();
    for (const auto& membership : memberships.value) {
      if (membership.group_id == group_id && membership.user_id == user_id) matching->push_back(membership);
    }
    if (matching->empty()) return answer->finish(Answer::failure(Fault::not_found, "the user is not in the group"));

    auto refused = std::make_shared<std::optional<Answer>>();
    in_turn<Membership>(
        matching, 0,
        [=](const Membership& membership, std::function<void()> next) {
          if (*refused) return next();
          self->_calls.remove_settled(kMemberships, membership.key, std::nullopt, executor, [=](store::Write removed) {
            if (!removed.ok() && removed.error != store::StoreError::removed) *refused = Answer::failure(fault_of(removed.error), removed.message);
            next();
          });
        },
        [=] {
          if (*refused) return answer->finish(std::move(**refused));
          self->_audit(actor, "group.member.remove", group_id, "user " + user_id, executor, [answer] { answer->finish(Answer::success()); });
        });
  });
}

// Two adds racing can each write a membership, since neither sees the other's; both mean
// the same, so each user or group is answered once.
void Directory::members(std::string group_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const {
  using Answer = Outcome<std::vector<std::string>>;
  auto answer = answering<std::vector<std::string>>(deadline, executor, std::move(done), kReadLate);
  _memberships(executor, [answer, group_id](Outcome<std::vector<Membership>> memberships) {
    if (!memberships.ok()) return answer->finish(Answer::from(memberships));
    std::set<std::string> out;
    for (const auto& membership : memberships.value) {
      if (membership.group_id == group_id) out.insert(membership.user_id);
    }
    answer->finish(Answer::success(std::vector<std::string>(out.begin(), out.end())));
  });
}

void Directory::allocate_numbers(audit::Actor actor, Deadline deadline, Executor executor, Done<Outcome<Numbered>> done) {
  using Answer = Outcome<Numbered>;
  auto answer = answering<Numbered>(deadline, executor, std::move(done), kChangeLate);
  if (!_numbers) return answer->finish(Answer::failure(Fault::refused, "no POSIX number range is configured"));
  auto self = shared_from_this();
  users(kBackfillDeadline, executor, [=](Outcome<std::vector<User>> all_users) {
    if (!all_users.ok()) return answer->finish(Answer::from(all_users));
    self->groups(kBackfillDeadline, executor, [=](Outcome<std::vector<Group>> all_groups) {
      if (!all_groups.ok()) return answer->finish(Answer::from(all_groups));
      auto people = std::make_shared<std::vector<User>>();
      for (const auto& one : all_users.value) {
        if (one.kind == Kind::person && !one.posix_number) people->push_back(one);
      }
      auto teams = std::make_shared<std::vector<Group>>();
      for (const auto& one : all_groups.value) {
        if (!one.posix_number) teams->push_back(one);
      }
      std::stable_sort(people->begin(), people->end(), [](const User& a, const User& b) { return a.created < b.created; });
      std::stable_sort(teams->begin(), teams->end(), [](const Group& a, const Group& b) { return a.created < b.created; });

      auto counted = std::make_shared<Numbered>();
      auto failure = std::make_shared<std::optional<Answer>>();
      const auto finish = [=] {
        // One entry for the pass, whatever came of it, as well as each record's own.
        self->_audit(actor, "ldap.posix.allocate", "directory", std::to_string(counted->users) + " users, " + std::to_string(counted->groups) + " groups",
                     executor, [=] { answer->finish(failure->value_or(Answer::success(*counted))); });
      };
      in_turn<User>(
          people, 0,
          [=](const User& user, std::function<void()> next) {
            if (*failure) return next();
            self->_numbers->next_user(executor, [=](Outcome<std::uint32_t> number) {
              if (!number.ok()) {
                *failure = Answer::from(number);
                return next();
              }
              auto numbered = user;
              numbered.posix_number = number.value;
              self->_put_user(actor, std::move(numbered), user.version, "user.update", "POSIX number", executor, [=](Outcome<User> put) {
                if (put.ok()) {
                  ++counted->users;
                } else {
                  *failure = Answer::from(put);
                }
                next();
              });
            });
          },
          [=] {
            in_turn<Group>(
                teams, 0,
                [=](const Group& group, std::function<void()> next) {
                  if (*failure) return next();
                  self->_numbers->next_group(executor, [=](Outcome<std::uint32_t> number) {
                    if (!number.ok()) {
                      *failure = Answer::from(number);
                      return next();
                    }
                    auto numbered = group;
                    numbered.posix_number = number.value;
                    self->_put_group(actor, std::move(numbered), group.version, "group.update", executor, [=](Outcome<Group> put) {
                      if (put.ok()) {
                        ++counted->groups;
                      } else {
                        *failure = Answer::from(put);
                      }
                      next();
                    });
                  });
                },
                finish);
          });
    });
  });
}

void Directory::memberships(Deadline deadline, Executor executor, Done<Outcome<std::vector<Membership>>> done) const {
  auto answer = answering<std::vector<Membership>>(deadline, executor, std::move(done), kReadLate);
  _memberships(executor, [answer](Outcome<std::vector<Membership>> memberships) { answer->finish(std::move(memberships)); });
}

void Directory::groups_of(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const {
  using Answer = Outcome<std::vector<std::string>>;
  auto answer = answering<std::vector<std::string>>(deadline, executor, std::move(done), kReadLate);
  _memberships(executor, [answer, user_id](Outcome<std::vector<Membership>> memberships) {
    if (!memberships.ok()) return answer->finish(Answer::from(memberships));
    std::set<std::string> out;
    for (const auto& membership : memberships.value) {
      if (membership.user_id == user_id) out.insert(membership.group_id);
    }
    answer->finish(Answer::success(std::vector<std::string>(out.begin(), out.end())));
  });
}

// ---------------------------------------------------------------- steps

std::optional<std::string> Directory::_new_id() {
  const auto bytes = dannan::identity::random_bytes(kIdBytes);
  if (bytes.empty()) return std::nullopt;
  return dannan::identity::hex(bytes);
}

void Directory::_user(std::string id, Executor executor, Done<Outcome<std::optional<User>>> done) const {
  using Answer = Outcome<std::optional<User>>;
  _calls.get_settled(kUsers, std::move(id), std::move(executor), [done = std::move(done)](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    done(Answer::success(record.value ? user_of(*record.value) : std::nullopt));
  });
}

void Directory::_group(std::string id, Executor executor, Done<Outcome<std::optional<Group>>> done) const {
  using Answer = Outcome<std::optional<Group>>;
  _calls.get_settled(kGroups, std::move(id), std::move(executor), [done = std::move(done)](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    done(Answer::success(record.value ? group_of(*record.value) : std::nullopt));
  });
}

void Directory::_memberships(Executor executor, Done<Outcome<std::vector<Membership>>> done) const {
  using Answer = Outcome<std::vector<Membership>>;
  _calls.list_settled(kMemberships, std::move(executor), [done = std::move(done)](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return done(Answer::from(records));
    std::vector<Membership> out;
    for (const auto& record : records.value) {
      auto membership = decode_membership(record.value);
      if (!membership) continue;
      membership->key = record.key;
      out.push_back(std::move(*membership));
    }
    done(Answer::success(std::move(out)));
  });
}

void Directory::_free(std::string table, std::string index, std::string value, std::string taken, Executor executor, Done<Outcome<Nothing>> refused,
                      Then then) const {
  if (value.empty()) return then();
  _calls.find_settled(std::move(table), std::move(index), std::move(value), std::move(executor),
                      [taken = std::move(taken), refused = std::move(refused), then = std::move(then)](Outcome<std::optional<store::Record>> found) {
                        if (!found.ok()) return refused(Outcome<Nothing>::from(found));
                        if (found.value) return refused(Outcome<Nothing>::failure(Fault::duplicate, taken));
                        then();
                      });
}

void Directory::_put_user(audit::Actor actor, User user, std::uint64_t expected, std::string action, std::string detail, Executor executor,
                          Done<Outcome<User>> done) {
  using Answer = Outcome<User>;
  const auto id = user.id;
  _calls.put_settled(kUsers, id, encode(user), expected, executor,
                     [self = shared_from_this(), actor, user = std::move(user), action = std::move(action), detail = std::move(detail), executor,
                      done = std::move(done)](store::Write written) mutable {
                       if (!written.ok()) return done(Answer::failure(fault_of(written.error), written.message));
                       user.version = written.version;
                       const auto subject = user.id;
                       self->_audit(actor, std::move(action), subject, std::move(detail), executor,
                                    [user = std::move(user), done = std::move(done)]() mutable { done(Answer::success(std::move(user))); });
                     });
}

void Directory::_put_group(audit::Actor actor, Group group, std::uint64_t expected, std::string action, Executor executor, Done<Outcome<Group>> done) {
  using Answer = Outcome<Group>;
  const auto id = group.id;
  _calls.put_settled(
      kGroups, id, encode(group), expected, executor,
      [self = shared_from_this(), actor, group = std::move(group), action = std::move(action), executor, done = std::move(done)](store::Write written) mutable {
        if (!written.ok()) return done(Answer::failure(fault_of(written.error), written.message));
        group.version = written.version;
        const auto subject = group.id;
        const auto name = group.name;
        self->_audit(actor, std::move(action), subject, name, executor,
                     [group = std::move(group), done = std::move(done)]() mutable { done(Answer::success(std::move(group))); });
      });
}

void Directory::_remove_memberships(std::function<bool(const Membership&)> matches, Executor executor, Then then) {
  auto self = shared_from_this();
  _memberships(executor, [=](Outcome<std::vector<Membership>> memberships) {
    if (!memberships.ok()) {
      self->_logger.error("cannot read memberships to remove: " + memberships.message);
      return then();
    }
    auto matching = std::make_shared<std::vector<Membership>>();
    for (const auto& membership : memberships.value) {
      if (matches(membership)) matching->push_back(membership);
    }
    in_turn<Membership>(
        matching, 0,
        [=](const Membership& membership, std::function<void()> next) {
          self->_calls.remove_settled(kMemberships, membership.key, std::nullopt, executor, [next](store::Write) { next(); });
        },
        then);
  });
}

void Directory::_audit(const audit::Actor& actor, std::string action, std::string subject, std::string detail, Executor executor, Then then) {
  // A failure is logged by the audit log itself; the change has been made.
  _audit_log->record(audit::Event{std::move(action), actor.id, std::move(subject), actor.source, std::move(detail)}, kAuditDeadline, std::move(executor),
                     [then = std::move(then)](Status) { then(); });
}

}  // namespace lugh::directory

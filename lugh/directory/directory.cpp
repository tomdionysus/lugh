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
    : _logger(std::move(log), "directory"), _store(std::move(store)), _wall(wall), _audit_log(std::move(audit)) {}

void Directory::dependent_add(std::shared_ptr<Dependent> dependent) { _dependents.push_back(std::move(dependent)); }

Task<Outcome<User>> Directory::create_user(audit::Actor actor, NewUser fresh) {
  using Answer = Outcome<User>;
  const auto name = normal_name(fresh.name);
  if (!name) co_return Answer::failure(Fault::invalid, kNameRule);

  std::string email;
  if (!fresh.email.empty()) {
    const auto normal = normal_email(fresh.email);
    if (!normal) co_return Answer::failure(Fault::invalid, "not an email address");
    email = *normal;
  }
  if (!printable(fresh.display_name, kMostDisplayBytes)) co_return Answer::failure(Fault::invalid, "a display name is printable UTF-8, at most 128 bytes");

  if (co_await _store->find(kUsers, "name", *name)) co_return Answer::failure(Fault::duplicate, "the name " + *name + " is taken");
  if (!email.empty() && co_await _store->find(kUsers, "email", email)) co_return Answer::failure(Fault::duplicate, "the address " + email + " is taken");

  const auto id = _new_id();
  if (!id) co_return Answer::failure(Fault::failed, "no randomness for an ID");

  User user;
  user.id = *id;
  user.kind = fresh.kind;
  user.enrolled = fresh.kind == Kind::service;
  user.name = *name;
  user.email = email;
  user.display_name = std::move(fresh.display_name);
  user.created = user.updated = (_wall.unix_ms() / 1000);
  co_return co_await _put_user(actor, std::move(user), 0, "user.create", fresh.kind == Kind::service ? "service" : "person");
}

Task<std::optional<User>> Directory::user(std::string id) const {
  const auto record = co_await _store->get(kUsers, std::move(id));
  co_return record ? user_of(*record) : std::nullopt;
}

Task<std::optional<User>> Directory::user_by_name(std::string name) const {
  const auto normal = normal_name(name);
  if (!normal) co_return std::nullopt;
  const auto record = co_await _store->find(kUsers, "name", *normal);
  co_return record ? user_of(*record) : std::nullopt;
}

Task<std::optional<User>> Directory::user_by_email(std::string email) const {
  const auto normal = normal_email(email);
  if (!normal) co_return std::nullopt;
  const auto record = co_await _store->find(kUsers, "email", *normal);
  co_return record ? user_of(*record) : std::nullopt;
}

Task<std::optional<User>> Directory::user_by_login(std::string login) const {
  if (login.find('@') == std::string::npos) co_return co_await user_by_name(std::move(login));
  co_return co_await user_by_email(std::move(login));
}

Task<std::vector<User>> Directory::users() const {
  std::vector<User> out;
  for (const auto& record : co_await _store->list(kUsers)) {
    if (auto user = user_of(record)) out.push_back(std::move(*user));
  }
  co_return out;
}

Task<Outcome<User>> Directory::update_user(audit::Actor actor, std::string id, UserChange change, std::optional<std::uint64_t> expected) {
  using Answer = Outcome<User>;
  auto found = co_await user(id);
  if (!found) co_return Answer::failure(Fault::not_found, "no such user");
  if (expected && *expected != found->version) co_return Answer::failure(Fault::conflict, "the user has changed since it was read");
  const auto version = found->version;

  std::vector<std::string> changed;
  if (change.name) {
    const auto name = normal_name(*change.name);
    if (!name) co_return Answer::failure(Fault::invalid, kNameRule);
    if (*name != found->name) {
      if (co_await _store->find(kUsers, "name", *name)) co_return Answer::failure(Fault::duplicate, "the name " + *name + " is taken");
      changed.push_back("name " + found->name + " to " + *name);
      found->name = *name;
    }
  }
  if (change.email) {
    std::string email;
    if (!change.email->empty()) {
      const auto normal = normal_email(*change.email);
      if (!normal) co_return Answer::failure(Fault::invalid, "not an email address");
      email = *normal;
    }
    if (email != found->email) {
      if (!email.empty() && co_await _store->find(kUsers, "email", email)) co_return Answer::failure(Fault::duplicate, "the address " + email + " is taken");
      changed.push_back("email");
      found->email = email;
    }
  }
  if (change.display_name) {
    if (!printable(*change.display_name, kMostDisplayBytes)) co_return Answer::failure(Fault::invalid, "a display name is printable UTF-8, at most 128 bytes");
    if (*change.display_name != found->display_name) {
      changed.push_back("display name");
      found->display_name = *change.display_name;
    }
  }

  if (changed.empty()) co_return Answer::success(std::move(*found));
  found->updated = (_wall.unix_ms() / 1000);
  co_return co_await _put_user(actor, std::move(*found), version, "user.update", join_change(changed));
}

Task<Outcome<User>> Directory::disable_user(audit::Actor actor, std::string id, bool disabled, std::optional<std::uint64_t> expected) {
  using Answer = Outcome<User>;
  auto found = co_await user(id);
  if (!found) co_return Answer::failure(Fault::not_found, "no such user");
  if (expected && *expected != found->version) co_return Answer::failure(Fault::conflict, "the user has changed since it was read");
  if (found->disabled == disabled) co_return Answer::success(std::move(*found));

  const auto version = found->version;
  found->disabled = disabled;
  found->updated = (_wall.unix_ms() / 1000);
  co_return co_await _put_user(actor, std::move(*found), version, disabled ? "user.disable" : "user.enable", {});
}

Task<Outcome<User>> Directory::enrolled_set(audit::Actor actor, std::string id, bool enrolled) {
  using Answer = Outcome<User>;
  auto found = co_await user(id);
  if (!found) co_return Answer::failure(Fault::not_found, "no such user");
  if (found->enrolled == enrolled) co_return Answer::success(std::move(*found));

  const auto version = found->version;
  found->enrolled = enrolled;
  found->updated = (_wall.unix_ms() / 1000);
  co_return co_await _put_user(actor, std::move(*found), version, enrolled ? "user.enrolled" : "user.unenrolled", {});
}

Task<Outcome<>> Directory::remove_user(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected) {
  using Answer = Outcome<>;
  const auto found = co_await user(id);
  if (!found) co_return Answer::failure(Fault::not_found, "no such user");
  if (expected && *expected != found->version) co_return Answer::failure(Fault::conflict, "the user has changed since it was read");

  // The user record goes first and conditionally: if it fails, nothing else has been
  // touched; once it is gone, the rest is tidying that a retry can finish.
  const auto removed = co_await _store->remove(kUsers, id, found->version);
  if (!removed.ok()) co_return Answer::failure(fault_of(removed.error), removed.message);
  co_await _audit(actor, "user.remove", found->id, found->name);

  for (const auto& membership : co_await _memberships()) {
    if (membership.user_id == id) co_await _store->remove(kMemberships, membership.key);
  }
  for (const auto& dependent : _dependents) {
    if (const auto forgotten = co_await dependent->forget(actor, found->id); !forgotten.ok)
      _logger.error("removing user " + found->id + ": " + forgotten.error);
  }
  co_return Answer::success();
}

Task<Outcome<Group>> Directory::create_group(audit::Actor actor, std::string name, std::string description) {
  using Answer = Outcome<Group>;
  const auto normal = normal_name(name);
  if (!normal) co_return Answer::failure(Fault::invalid, kNameRule);
  if (!printable(description, kMostDescriptionBytes)) co_return Answer::failure(Fault::invalid, "a description is printable UTF-8, at most 1024 bytes");
  if (co_await _store->find(kGroups, "name", *normal)) co_return Answer::failure(Fault::duplicate, "the name " + *normal + " is taken");

  const auto id = _new_id();
  if (!id) co_return Answer::failure(Fault::failed, "no randomness for an ID");

  Group group;
  group.id = *id;
  group.name = *normal;
  group.description = std::move(description);
  group.created = group.updated = (_wall.unix_ms() / 1000);
  co_return co_await _put_group(actor, std::move(group), 0, "group.create");
}

Task<std::optional<Group>> Directory::group(std::string id) const {
  const auto record = co_await _store->get(kGroups, std::move(id));
  co_return record ? group_of(*record) : std::nullopt;
}

Task<std::optional<Group>> Directory::group_by_name(std::string name) const {
  const auto normal = normal_name(name);
  if (!normal) co_return std::nullopt;
  const auto record = co_await _store->find(kGroups, "name", *normal);
  co_return record ? group_of(*record) : std::nullopt;
}

Task<std::vector<Group>> Directory::groups() const {
  std::vector<Group> out;
  for (const auto& record : co_await _store->list(kGroups)) {
    if (auto group = group_of(record)) out.push_back(std::move(*group));
  }
  co_return out;
}

Task<Outcome<Group>> Directory::update_group(audit::Actor actor, std::string id, GroupChange change, std::optional<std::uint64_t> expected) {
  using Answer = Outcome<Group>;
  auto found = co_await group(id);
  if (!found) co_return Answer::failure(Fault::not_found, "no such group");
  if (expected && *expected != found->version) co_return Answer::failure(Fault::conflict, "the group has changed since it was read");
  const auto version = found->version;

  bool changed = false;
  if (change.name) {
    const auto name = normal_name(*change.name);
    if (!name) co_return Answer::failure(Fault::invalid, kNameRule);
    if (*name != found->name) {
      if (co_await _store->find(kGroups, "name", *name)) co_return Answer::failure(Fault::duplicate, "the name " + *name + " is taken");
      found->name = *name;
      changed = true;
    }
  }
  if (change.description) {
    if (!printable(*change.description, kMostDescriptionBytes))
      co_return Answer::failure(Fault::invalid, "a description is printable UTF-8, at most 1024 bytes");
    if (*change.description != found->description) {
      found->description = *change.description;
      changed = true;
    }
  }

  if (!changed) co_return Answer::success(std::move(*found));
  found->updated = (_wall.unix_ms() / 1000);
  co_return co_await _put_group(actor, std::move(*found), version, "group.update");
}

Task<Outcome<>> Directory::remove_group(audit::Actor actor, std::string id, std::optional<std::uint64_t> expected) {
  using Answer = Outcome<>;
  const auto found = co_await group(id);
  if (!found) co_return Answer::failure(Fault::not_found, "no such group");
  if (expected && *expected != found->version) co_return Answer::failure(Fault::conflict, "the group has changed since it was read");

  const auto removed = co_await _store->remove(kGroups, id, found->version);
  if (!removed.ok()) co_return Answer::failure(fault_of(removed.error), removed.message);
  co_await _audit(actor, "group.remove", found->id, found->name);

  for (const auto& membership : co_await _memberships()) {
    if (membership.group_id == id) co_await _store->remove(kMemberships, membership.key);
  }
  co_return Answer::success();
}

Task<Outcome<>> Directory::add_member(audit::Actor actor, std::string group_id, std::string user_id) {
  using Answer = Outcome<>;
  if (!co_await group(group_id)) co_return Answer::failure(Fault::not_found, "no such group");
  if (!co_await user(user_id)) co_return Answer::failure(Fault::not_found, "no such user");

  for (const auto& membership : co_await _memberships()) {
    if (membership.group_id == group_id && membership.user_id == user_id) co_return Answer::success();
  }

  const auto instance = dannan::identity::random_bytes(8);
  if (instance.empty()) co_return Answer::failure(Fault::failed, "no randomness for an ID");

  Membership membership;
  membership.group_id = group_id;
  membership.user_id = user_id;
  membership.added = (_wall.unix_ms() / 1000);
  const auto key = membership.group_id + "/" + membership.user_id + "/" + dannan::identity::hex(instance);

  const auto written = co_await _store->put(kMemberships, key, encode(membership), 0);
  if (!written.ok()) co_return Answer::failure(fault_of(written.error), written.message);
  co_await _audit(actor, "group.member.add", membership.group_id, "user " + membership.user_id);
  co_return Answer::success();
}

Task<Outcome<>> Directory::remove_member(audit::Actor actor, std::string group_id, std::string user_id) {
  using Answer = Outcome<>;
  bool found = false;
  for (const auto& membership : co_await _memberships()) {
    if (membership.group_id != group_id || membership.user_id != user_id) continue;
    const auto removed = co_await _store->remove(kMemberships, membership.key);
    if (!removed.ok() && removed.error != store::StoreError::removed) co_return Answer::failure(fault_of(removed.error), removed.message);
    found = true;
  }
  if (!found) co_return Answer::failure(Fault::not_found, "the user is not in the group");
  co_await _audit(actor, "group.member.remove", group_id, "user " + user_id);
  co_return Answer::success();
}

// Two adds racing can each write a membership, since neither sees the other's; both mean
// the same, so each user or group is answered once.
Task<std::vector<std::string>> Directory::members(std::string group_id) const {
  std::set<std::string> out;
  for (const auto& membership : co_await _memberships()) {
    if (membership.group_id == group_id) out.insert(membership.user_id);
  }
  co_return std::vector<std::string>(out.begin(), out.end());
}

Task<std::vector<std::string>> Directory::groups_of(std::string user_id) const {
  std::set<std::string> out;
  for (const auto& membership : co_await _memberships()) {
    if (membership.user_id == user_id) out.insert(membership.group_id);
  }
  co_return std::vector<std::string>(out.begin(), out.end());
}

std::optional<std::string> Directory::_new_id() {
  const auto bytes = dannan::identity::random_bytes(kIdBytes);
  if (bytes.empty()) return std::nullopt;
  return dannan::identity::hex(bytes);
}

Task<std::vector<Membership>> Directory::_memberships() const {
  std::vector<Membership> out;
  for (const auto& record : co_await _store->list(kMemberships)) {
    auto membership = decode_membership(record.value);
    if (!membership) continue;
    membership->key = record.key;
    out.push_back(std::move(*membership));
  }
  co_return out;
}

Task<Outcome<User>> Directory::_put_user(audit::Actor actor, User user, std::uint64_t expected, std::string action, std::string detail) {
  using Answer = Outcome<User>;
  const auto written = co_await _store->put(kUsers, user.id, encode(user), expected);
  if (!written.ok()) co_return Answer::failure(fault_of(written.error), written.message);
  user.version = written.version;
  co_await _audit(actor, std::move(action), user.id, std::move(detail));
  co_return Answer::success(std::move(user));
}

Task<Outcome<Group>> Directory::_put_group(audit::Actor actor, Group group, std::uint64_t expected, std::string action) {
  using Answer = Outcome<Group>;
  const auto written = co_await _store->put(kGroups, group.id, encode(group), expected);
  if (!written.ok()) co_return Answer::failure(fault_of(written.error), written.message);
  group.version = written.version;
  co_await _audit(actor, std::move(action), group.id, group.name);
  co_return Answer::success(std::move(group));
}

Task<void> Directory::_audit(const audit::Actor& actor, std::string action, std::string subject, std::string detail) {
  // A failure is logged by the audit log itself; the change has been made.
  co_await awaited<Status>([&](Executor executor, Done<Status> done) {
    _audit_log->record(audit::Event{std::move(action), actor.id, std::move(subject), actor.source, std::move(detail)}, kTransitionDeadline, std::move(executor),
                       std::move(done));
  });
}

}  // namespace lugh::directory

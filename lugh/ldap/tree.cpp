//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/tree.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <map>
#include <stdexcept>

#include "lugh/core/steps.h"

namespace lugh::ldap {

namespace {

constexpr Deadline kStepDeadline = std::chrono::seconds(15);
constexpr const char* kPeople = "people";
constexpr const char* kServices = "services";
constexpr const char* kGroups = "groups";

// RFC 4517 section 3.3.13, in UTC.
std::string generalized_time(std::uint64_t seconds) {
  const auto when = static_cast<std::time_t>(seconds);
  std::tm parts{};
  gmtime_r(&when, &parts);
  char out[32];
  std::snprintf(out, sizeof(out), "%04d%02d%02d%02d%02d%02dZ", parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday, parts.tm_hour, parts.tm_min,
                parts.tm_sec);
  return out;
}

std::string with_name(std::string pattern, const std::string& name) {
  const std::string token = "{name}";
  for (auto at = pattern.find(token); at != std::string::npos; at = pattern.find(token, at + name.size())) pattern.replace(at, token.size(), name);
  return pattern;
}

Listed failed(const std::string& why) { return Listed{ResultCode::unavailable, why, {}, {}}; }
Listed not_there() { return Listed{ResultCode::no_such_object, "no such entry", {}, {}}; }

}  // namespace

// What a walk has read: the entries it may answer with, and those they point at.
struct Tree::Loaded {
  std::vector<directory::User> users;
  std::vector<directory::Group> groups;
  // Group ID to user IDs, for those read.
  std::map<std::string, std::vector<std::string>> members;
  // Those related to an entry and not themselves answers.
  std::vector<directory::User> other_users;
  std::vector<directory::Group> other_groups;
};

Tree::Tree(std::shared_ptr<directory::Directory> directory, Settings settings) : _directory(std::move(directory)), _settings(std::move(settings)) {
  const auto base = parse_dn(_settings.base_dn);
  if (!base || base->empty()) throw std::invalid_argument("ldap.base_dn is not a distinguished name: " + _settings.base_dn);
  _base = *base;
  _normal_base = normalised(_base);
}

Place Tree::locate(const Dn& dn) const {
  const auto normal = normalised(dn);
  if (!within(normal, _normal_base)) return {};
  const auto below = normal.rdns.size() - _normal_base.rdns.size();
  if (below == 0) return {Place::Kind::base, {}};
  const auto& container = normal.rdns[below - 1];
  if (container.type != "ou" || below > 2) return {};
  Place::Kind kind;
  if (container.value == kPeople) {
    kind = Place::Kind::people;
  } else if (container.value == kServices) {
    kind = Place::Kind::services;
  } else if (container.value == kGroups) {
    kind = Place::Kind::groups;
  } else {
    return {};
  }
  if (below == 1) return {kind, {}};
  const auto& leaf = normal.rdns[0];
  if (kind == Place::Kind::groups) {
    if (leaf.type != "cn") return {};
    return {Place::Kind::group, leaf.value};
  }
  if (leaf.type != "uid") return {};
  return {kind == Place::Kind::people ? Place::Kind::person : Place::Kind::service, leaf.value};
}

std::string Tree::dn_of(const directory::User& user) const {
  return "uid=" + escape_dn_value(user.name) + ",ou=" + (user.kind == directory::Kind::service ? kServices : kPeople) + "," + base_text();
}

std::string Tree::dn_of(const directory::Group& group) const { return "cn=" + escape_dn_value(group.name) + ",ou=" + kGroups + "," + base_text(); }

Entry Tree::_container(Place::Kind kind) const {
  Entry entry;
  entry.add("objectClass", "top");
  if (kind == Place::Kind::base) {
    entry.dn = base_text();
    entry.add("objectClass", "organization");
    if (_base.rdns[0].type == "dc") entry.add("objectClass", "dcObject");
    entry.add(_base.rdns[0].type, _base.rdns[0].value);
    if (_base.rdns[0].type != "o") entry.add("o", _base.rdns[0].value);
    return entry;
  }
  const char* name = kind == Place::Kind::people ? kPeople : kind == Place::Kind::services ? kServices : kGroups;
  entry.dn = std::string("ou=") + name + "," + base_text();
  entry.add("objectClass", "organizationalUnit");
  entry.add("ou", name);
  return entry;
}

Entry Tree::_person(const directory::User& user, const std::vector<const directory::Group*>& groups, std::optional<std::uint32_t> primary_gid) const {
  Entry entry;
  entry.dn = dn_of(user);
  for (const auto* name : {"top", "person", "organizationalPerson", "inetOrgPerson"}) entry.add("objectClass", name);
  const auto& shown = user.display_name.empty() ? user.name : user.display_name;
  entry.add("uid", user.name);
  entry.add("cn", shown);
  entry.add("displayName", shown);
  // inetOrgPerson requires sn: the display name whole until a family name is set.
  entry.add("sn", user.family_name.empty() ? shown : user.family_name);
  if (!user.given_name.empty()) entry.add("givenName", user.given_name);
  if (!user.email.empty()) entry.add("mail", user.email);
  // Without a primary group a number cannot make a whole posixAccount.
  if (user.kind == directory::Kind::person && user.posix_number && primary_gid) {
    entry.add("objectClass", "posixAccount");
    entry.add("uidNumber", std::to_string(*user.posix_number));
    entry.add("gidNumber", std::to_string(*primary_gid));
    entry.add("homeDirectory", with_name(_settings.home, user.name));
    entry.add("loginShell", _settings.shell);
  }
  for (const auto* group : groups) entry.add("memberOf", dn_of(*group));
  entry.add("entryUUID", user.id);
  entry.add("createTimestamp", generalized_time(user.created));
  entry.add("modifyTimestamp", generalized_time(user.updated));
  entry.add("lughEntryVersion", std::to_string(user.version));
  return entry;
}

Entry Tree::_group(const directory::Group& group, const std::vector<const directory::User*>& members) const {
  Entry entry;
  entry.dn = dn_of(group);
  for (const auto* name : {"top", "groupOfNames"}) entry.add("objectClass", name);
  entry.add("cn", group.name);
  if (!group.description.empty()) entry.add("description", group.description);
  for (const auto* member : members) entry.add("member", dn_of(*member));
  if (group.posix_number) {
    entry.add("objectClass", "posixGroup");
    entry.add("gidNumber", std::to_string(*group.posix_number));
  }
  entry.add("entryUUID", group.id);
  entry.add("createTimestamp", generalized_time(group.created));
  entry.add("modifyTimestamp", generalized_time(group.updated));
  entry.add("lughEntryVersion", std::to_string(group.version));
  return entry;
}

void Tree::walk(Walk walk, Deadline deadline, Executor executor, Done<Listed> done) const {
  auto answer = Completion<Listed>::start(deadline, executor, std::move(done),
                                          [] { return Listed{ResultCode::time_limit_exceeded, "the search did not finish within its limit", {}, {}}; });
  const auto place = locate(walk.base);
  if (place.kind == Place::Kind::outside) return answer->finish(not_there());
  auto held = std::make_shared<const Walk>(std::move(walk));
  auto self = shared_from_this();

  const auto with_user = [=](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer->finish(failed(found.message));
    self->_load_user(held, place, found.value, executor, answer);
  };

  // A base that is one entry is that entry, whatever the filter says.
  if (place.leaf()) {
    if (place.kind == Place::Kind::group) {
      return _directory->group_by_name(place.name, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> found) {
        if (!found.ok()) return answer->finish(failed(found.message));
        if (!found.value) return answer->finish(not_there());
        self->_load_group(held, place, found.value, executor, answer);
      });
    }
    return _directory->user_by_name(place.name, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
      if (!found.ok()) return answer->finish(failed(found.message));
      const auto wanted = place.kind == Place::Kind::service ? directory::Kind::service : directory::Kind::person;
      if (!found.value || found.value->kind != wanted) return answer->finish(not_there());
      self->_load_user(held, place, found.value, executor, answer);
    });
  }

  // A container on its own is known without reading anything.
  if (held->scope == Scope::base) return _answer(held, place, Loaded{}, answer);

  // The shape every PAM, SSSD and mail lookup has: one record, not all of them.
  {
    const bool below_groups = place.kind == Place::Kind::groups;
    if (!below_groups) {
      if (const auto uid = pinned_value(held->filter, "uid")) return _directory->user_by_name(fold(*uid), kStepDeadline, executor, with_user);
      if (const auto mail = pinned_value(held->filter, "mail")) return _directory->user_by_email(fold(*mail), kStepDeadline, executor, with_user);
    } else if (const auto cn = pinned_value(held->filter, "cn")) {
      return _directory->group_by_name(fold(*cn), kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> found) {
        if (!found.ok()) return answer->finish(failed(found.message));
        self->_load_group(held, place, found.value, executor, answer);
      });
    }
    if (const auto id = pinned_value(held->filter, "entryuuid")) {
      return _directory->user(*id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
        if (!found.ok()) return answer->finish(failed(found.message));
        if (found.value) return self->_load_user(held, place, found.value, executor, answer);
        self->_directory->group(*id, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> group) {
          if (!group.ok()) return answer->finish(failed(group.message));
          self->_load_group(held, place, group.value, executor, answer);
        });
      });
    }
  }
  _load_all(held, place, executor, answer);
}

void Tree::_load_all(std::shared_ptr<const Walk> walk, Place place, Executor executor, std::shared_ptr<Completion<Listed>> answer) const {
  auto self = shared_from_this();
  // A search of one container of the base reads what it needs of the rest only to fill it in.
  _directory->users(kStepDeadline, executor, [=](Outcome<std::vector<directory::User>> users) {
    if (!users.ok()) return answer->finish(failed(users.message));
    self->_directory->groups(kStepDeadline, executor, [=](Outcome<std::vector<directory::Group>> groups) {
      if (!groups.ok()) return answer->finish(failed(groups.message));
      self->_directory->memberships(kStepDeadline, executor, [=](Outcome<std::vector<directory::Membership>> memberships) {
        if (!memberships.ok()) return answer->finish(failed(memberships.message));
        Loaded loaded;
        loaded.users = users.value;
        loaded.groups = groups.value;
        for (const auto& one : memberships.value) loaded.members[one.group_id].push_back(one.user_id);
        self->_answer(walk, place, loaded, answer);
      });
    });
  });
}

void Tree::_load_user(std::shared_ptr<const Walk> walk, Place place, std::optional<directory::User> user, Executor executor,
                      std::shared_ptr<Completion<Listed>> answer) const {
  auto self = shared_from_this();
  if (!user) return _answer(walk, place, Loaded{}, answer);
  _directory->groups_of(user->id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> group_ids) {
    if (!group_ids.ok()) return answer->finish(failed(group_ids.message));
    auto loaded = std::make_shared<Loaded>();
    loaded->users.push_back(*user);
    auto ids = std::make_shared<std::vector<std::string>>(group_ids.value);
    const auto finish = [=] {
      if (self->_settings.primary_group.empty()) return self->_answer(walk, place, *loaded, answer);
      self->_directory->group_by_name(self->_settings.primary_group, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> primary) {
        if (!primary.ok()) return answer->finish(failed(primary.message));
        if (primary.value) loaded->other_groups.push_back(*primary.value);
        self->_answer(walk, place, *loaded, answer);
      });
    };
    in_turn<std::string>(
        ids, 0,
        [=](const std::string& id, std::function<void()> next) {
          self->_directory->group(id, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> group) {
            if (group.ok() && group.value) {
              loaded->other_groups.push_back(*group.value);
              loaded->members[id].push_back(user->id);
            }
            next();
          });
        },
        finish);
  });
}

void Tree::_load_group(std::shared_ptr<const Walk> walk, Place place, std::optional<directory::Group> group, Executor executor,
                       std::shared_ptr<Completion<Listed>> answer) const {
  auto self = shared_from_this();
  if (!group) return _answer(walk, place, Loaded{}, answer);
  _directory->members(group->id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> member_ids) {
    if (!member_ids.ok()) return answer->finish(failed(member_ids.message));
    auto loaded = std::make_shared<Loaded>();
    loaded->groups.push_back(*group);
    auto ids = std::make_shared<std::vector<std::string>>(member_ids.value);
    in_turn<std::string>(
        ids, 0,
        [=](const std::string& id, std::function<void()> next) {
          self->_directory->user(id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
            if (user.ok() && user.value) {
              loaded->other_users.push_back(*user.value);
              loaded->members[group->id].push_back(id);
            }
            next();
          });
        },
        [=] { self->_answer(walk, place, *loaded, answer); });
  });
}

void Tree::_answer(std::shared_ptr<const Walk> walk, const Place& place, const Loaded& loaded, const std::shared_ptr<Completion<Listed>>& answer) const {
  using Kind = Place::Kind;
  std::map<std::string, const directory::User*> users;
  std::map<std::string, const directory::Group*> groups;
  for (const auto& one : loaded.users) users[one.id] = &one;
  for (const auto& one : loaded.other_users) users[one.id] = &one;
  for (const auto& one : loaded.groups) groups[one.id] = &one;
  for (const auto& one : loaded.other_groups) groups[one.id] = &one;

  std::map<std::string, std::vector<const directory::Group*>> groups_of;
  for (const auto& [group_id, members] : loaded.members) {
    const auto group = groups.find(group_id);
    if (group == groups.end()) continue;
    for (const auto& user_id : members) groups_of[user_id].push_back(group->second);
  }

  std::optional<std::uint32_t> primary_gid;
  if (!_settings.primary_group.empty()) {
    for (const auto& [id, group] : groups) {
      if (group->name == _settings.primary_group) primary_gid = group->posix_number;
    }
  }

  // Each thing the walk covers, in order, under a key that stays put as the directory changes, so
  // a page token still means something on the next search.
  struct Candidate {
    std::string key;
    std::function<Entry()> make;
  };
  std::vector<Candidate> candidates;

  const auto covers = [&](Kind target) {
    if (walk->scope == Scope::base) return place.kind == target;
    if (place.kind == target) return walk->scope == Scope::subtree;
    if (place.kind == Kind::base) {
      if (target == Kind::people || target == Kind::services || target == Kind::groups) return true;
      return walk->scope == Scope::subtree;
    }
    return (place.kind == Kind::people && target == Kind::person) || (place.kind == Kind::services && target == Kind::service) ||
           (place.kind == Kind::groups && target == Kind::group);
  };

  for (const auto kind : {Kind::base, Kind::people, Kind::services, Kind::groups}) {
    if (covers(kind)) candidates.push_back({"0" + std::to_string(static_cast<int>(kind)), [this, kind] { return _container(kind); }});
  }
  for (const auto& user : loaded.users) {
    const auto kind = user.kind == directory::Kind::service ? Kind::service : Kind::person;
    if (!covers(kind)) continue;
    // A leaf's own base is only itself, and a pinned lookup may find someone outside the base.
    if (place.leaf() && place.name != user.name) continue;
    const auto* found = &user;
    const auto related = groups_of[user.id];
    candidates.push_back(
        {(kind == Kind::person ? "1" : "2") + user.name, [this, found, related, primary_gid] { return _person(*found, related, primary_gid); }});
  }
  for (const auto& group : loaded.groups) {
    if (!covers(Kind::group)) continue;
    if (place.leaf() && place.name != group.name) continue;
    std::vector<const directory::User*> members;
    const auto listed = loaded.members.find(group.id);
    if (listed != loaded.members.end()) {
      for (const auto& id : listed->second) {
        const auto member = users.find(id);
        if (member != users.end()) members.push_back(member->second);
      }
    }
    const auto* found = &group;
    candidates.push_back({"3" + group.name, [this, found, members] { return _group(*found, members); }});
  }
  std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) { return a.key < b.key; });

  Listed out;
  if (place.leaf()) {
    // What may not be seen is not there, whatever the scope or the filter says of it.
    bool seen = false;
    for (const auto& user : loaded.users) seen = seen || (user.name == place.name && walk->visible(_person(user, groups_of[user.id], primary_gid)));
    for (const auto& group : loaded.groups) seen = seen || (group.name == place.name && walk->visible(_group(group, {})));
    if (!seen) return answer->finish(not_there());
  }
  std::string last;
  for (const auto& candidate : candidates) {
    if (!walk->after.empty() && candidate.key <= walk->after) continue;
    auto entry = candidate.make();
    if (walk->filter.evaluate(entry) != Match::yes || !walk->visible(entry)) continue;
    // There is more: this page ends at the last one it holds.
    if (out.entries.size() == walk->most) {
      out.next = last;
      break;
    }
    out.entries.push_back(std::move(entry));
    last = candidate.key;
  }
  answer->finish(std::move(out));
}

}  // namespace lugh::ldap

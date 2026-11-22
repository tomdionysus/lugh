//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/writes.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <set>
#include <variant>

#include "lugh/core/steps.h"
#include "lugh/scopes/scope.h"

namespace lugh::ldap {

namespace {

constexpr Deadline kDeadline = std::chrono::seconds(30);
constexpr Deadline kStepDeadline = std::chrono::seconds(15);

Result refused(ResultCode code, const std::string& message) { return Result{code, "", message}; }

// TODO/2026-11-04-ldap.md, "Results".
template <typename T>
Result result_of(const Outcome<T>& outcome) {
  switch (outcome.fault) {
    case Fault::none:
      return {};
    case Fault::not_found:
      return refused(ResultCode::no_such_object, outcome.message);
    case Fault::conflict:
      return refused(ResultCode::assertion_failed, outcome.message);
    case Fault::duplicate:
      return refused(ResultCode::entry_already_exists, outcome.message);
    case Fault::invalid:
    case Fault::refused:
      return refused(ResultCode::constraint_violation, outcome.message);
    case Fault::failed:
    case Fault::unavailable:
    case Fault::timed_out:
      break;
  }
  return refused(ResultCode::unavailable, "the request could not be completed, and may yet be made");
}

std::shared_ptr<Completion<Result>> answering_result(Executor executor, Done<Result> done) {
  return Completion<Result>::start(kDeadline, std::move(executor), std::move(done),
                                   [] { return refused(ResultCode::unavailable, "the request did not finish in time, and may yet be made"); });
}

audit::Actor actor_of(const Writes::Asking& asking) { return audit::Actor{asking.bound.caller.id, "ldap:" + asking.address}; }

bool may_write(const Bound& bound) { return bound.caller.has_scope(scopes::kDirectoryWrite); }

bool may_see(const Bound& bound, const Dn& dn) {
  if (bound.caller.has_scope(scopes::kDirectoryRead)) return true;
  const auto own = parse_dn(bound.dn);
  return own && normalised(*own) == normalised(dn);
}

// The Assertion control's version, when that is what it asks about.
std::optional<std::uint64_t> version_in(const std::optional<Filter>& assertion) {
  if (!assertion) return std::nullopt;
  const auto text = pinned_value(*assertion, "lughentryversion");
  if (!text) return std::nullopt;
  std::uint64_t out = 0;
  const auto end = text->data() + text->size();
  const auto [at, error] = std::from_chars(text->data(), end, out);
  if (error != std::errc() || at != end) return std::nullopt;
  return out;
}

// What no write may touch, whatever the entry.
std::optional<Result> forbidden_attribute(const std::string& folded) {
  if (folded == "userpassword") return refused(ResultCode::unwilling_to_perform, "Password Modify is the only way to change a password");
  for (const auto* name : {"objectclass", "memberof", "uidnumber", "gidnumber", "homedirectory", "loginshell", "entryuuid", "createtimestamp",
                           "modifytimestamp", "lughentryversion"}) {
    if (folded == name) return refused(ResultCode::constraint_violation, "that attribute is read-only");
  }
  return std::nullopt;
}

std::optional<std::string> single_value(const Attribute& attribute) {
  if (attribute.values.size() != 1) return std::nullopt;
  return attribute.values.front();
}

// A person's or a service's changes as one update, so it succeeds or fails entire.
std::variant<directory::UserChange, Result> user_change_of(const directory::User& user, const std::vector<Change>& changes) {
  directory::UserChange out;
  for (const auto& change : changes) {
    const auto name = fold(change.attribute.type);
    if (auto bad = forbidden_attribute(name)) return *bad;
    if (name == "uid") return refused(ResultCode::constraint_violation, "a name changes through a rename");
    const bool known = name == "cn" || name == "displayname" || name == "givenname" || name == "sn" || name == "mail";
    if (!known) return refused(ResultCode::no_such_attribute, "that attribute is not one this entry can have");
    if (change.operation == ModifyOperation::add) return refused(ResultCode::unwilling_to_perform, "each of these holds one value: replace or delete it");

    const bool removing = change.operation == ModifyOperation::remove || change.attribute.values.empty();
    std::string value;
    if (!removing) {
      const auto one = single_value(change.attribute);
      if (!one) return refused(ResultCode::constraint_violation, "each of these holds one value");
      value = *one;
    }
    if (name == "cn" || name == "displayname") {
      if (removing) return refused(ResultCode::constraint_violation, "the entry needs a name to show");
      out.display_name = value;
    } else if (name == "givenname") {
      out.given_name = value;
    } else if (name == "sn") {
      out.family_name = value;
    } else {
      if (removing && user.kind == directory::Kind::person) return refused(ResultCode::constraint_violation, "a person must keep an address");
      out.email = value;
    }
  }
  return out;
}

bool has_folded(const std::vector<std::string>& values, std::string_view wanted) {
  return std::any_of(values.begin(), values.end(), [&](const std::string& one) { return fold(one) == wanted; });
}

// What an added entry may be: the classes the tree gives it, and it must be the structural one.
std::optional<Result> classes_ok(const std::vector<std::string>& given, const std::vector<std::string>& allowed, std::string_view structural) {
  if (!has_folded(given, structural)) return refused(ResultCode::object_class_violation, "not the object classes this part of the tree holds");
  for (const auto& one : given) {
    if (std::find(allowed.begin(), allowed.end(), fold(one)) == allowed.end()) {
      return refused(ResultCode::object_class_violation, "not the object classes this part of the tree holds");
    }
  }
  return std::nullopt;
}

}  // namespace

// What a write found at the DN it names.
struct Writes::Target {
  Place place;
  std::optional<directory::User> user;
  std::optional<directory::Group> group;
};

Writes::Writes(std::shared_ptr<Tree> tree, std::shared_ptr<directory::Directory> directory, std::shared_ptr<session::Sessions> sessions,
               std::shared_ptr<authn::Passwords> passwords, std::shared_ptr<authn::Authenticator> authenticator)
    : _tree(std::move(tree)),
      _directory(std::move(directory)),
      _sessions(std::move(sessions)),
      _passwords(std::move(passwords)),
      _authenticator(std::move(authenticator)) {}

void Writes::_checked(const Asking& asking, const std::string& text, Executor executor, std::shared_ptr<Completion<Result>> answer, Checked then) {
  const auto dn = parse_dn(text);
  if (!dn) return answer->finish(refused(ResultCode::invalid_dn_syntax, "not a distinguished name"));
  const auto place = _tree->locate(*dn);
  const auto not_there = refused(ResultCode::no_such_object, "no such entry");
  if (place.kind == Place::Kind::outside) return answer->finish(not_there);
  // What may not be seen is not there, for a write as for a read.
  if (!may_write(asking.bound)) {
    if (!may_see(asking.bound, *dn)) return answer->finish(not_there);
    return answer->finish(refused(ResultCode::insufficient_access_rights, "that needs lugh:directory.write"));
  }
  auto self = shared_from_this();
  if (place.kind == Place::Kind::group) {
    return _directory->group_by_name(place.name, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> found) {
      if (!found.ok()) return answer->finish(result_of(found));
      if (!found.value) return answer->finish(not_there);
      self->_with_assertion(asking, *dn, Target{place, std::nullopt, found.value}, executor, answer, then);
    });
  }
  if (place.leaf()) {
    return _directory->user_by_name(place.name, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
      if (!found.ok()) return answer->finish(result_of(found));
      const auto wanted = place.kind == Place::Kind::service ? directory::Kind::service : directory::Kind::person;
      if (!found.value || found.value->kind != wanted) return answer->finish(not_there);
      self->_with_assertion(asking, *dn, Target{place, found.value, std::nullopt}, executor, answer, then);
    });
  }
  _with_assertion(asking, *dn, Target{place, std::nullopt, std::nullopt}, executor, answer, then);
}

void Writes::_with_assertion(const Asking& asking, Dn dn, Target target, Executor executor, std::shared_ptr<Completion<Result>> answer, Checked then) {
  if (!asking.assertion) return then(std::move(target), std::nullopt);
  const auto expected = version_in(asking.assertion);
  Tree::Walk walk;
  walk.base = std::move(dn);
  walk.scope = Scope::base;
  walk.filter = *asking.assertion;
  walk.visible = [](const Entry&) { return true; };
  walk.most = 1;
  _tree->walk(std::move(walk), kStepDeadline, executor, [answer, then, target, expected](Listed listed) mutable {
    if (listed.code != ResultCode::success) return answer->finish(refused(listed.code, listed.message));
    if (listed.entries.empty()) return answer->finish(refused(ResultCode::assertion_failed, "the entry is not as the request asserted"));
    then(std::move(target), expected);
  });
}

void Writes::modify(Asking asking, ModifyRequest request, Executor executor, Done<Result> done) {
  auto answer = answering_result(executor, std::move(done));
  auto self = shared_from_this();
  auto held = std::make_shared<ModifyRequest>(std::move(request));
  _checked(asking, held->object, executor, answer, [=](Target target, std::optional<std::uint64_t> expected) {
    if (target.user) return self->_modify_user(asking, *target.user, expected, *held, executor, answer);
    if (target.group) return self->_modify_group(asking, *target.group, expected, *held, executor, answer);
    answer->finish(refused(ResultCode::unwilling_to_perform, "the fixed tree does not change"));
  });
}

void Writes::_modify_user(const Asking& asking, const directory::User& user, std::optional<std::uint64_t> expected, const ModifyRequest& request,
                          Executor executor, std::shared_ptr<Completion<Result>> answer) {
  auto change = user_change_of(user, request.changes);
  if (const auto* bad = std::get_if<Result>(&change)) return answer->finish(*bad);
  _directory->update_user(actor_of(asking), user.id, std::get<directory::UserChange>(std::move(change)), expected, kStepDeadline, executor,
                          [answer](Outcome<directory::User> changed) { answer->finish(result_of(changed)); });
}

void Writes::_modify_group(const Asking& asking, const directory::Group& group, std::optional<std::uint64_t> expected, const ModifyRequest& request,
                           Executor executor, std::shared_ptr<Completion<Result>> answer) {
  bool members = false;
  directory::GroupChange change;
  bool attributes = false;
  for (const auto& one : request.changes) {
    const auto name = fold(one.attribute.type);
    if (name == "member") {
      members = true;
      continue;
    }
    attributes = true;
    if (auto bad = forbidden_attribute(name)) return answer->finish(*bad);
    if (name == "cn") return answer->finish(refused(ResultCode::constraint_violation, "a name changes through a rename"));
    if (name != "description") return answer->finish(refused(ResultCode::no_such_attribute, "that attribute is not one this entry can have"));
    if (one.operation == ModifyOperation::add) return answer->finish(refused(ResultCode::unwilling_to_perform, "it holds one value: replace or delete it"));
    if (one.operation == ModifyOperation::remove || one.attribute.values.empty()) {
      change.description = "";
    } else {
      const auto value = single_value(one.attribute);
      if (!value) return answer->finish(refused(ResultCode::constraint_violation, "it holds one value"));
      change.description = *value;
    }
  }
  if (members && attributes)
    return answer->finish(refused(ResultCode::unwilling_to_perform, "a group's attributes and its members change in separate requests"));
  if (members) return _modify_members(asking, group, request, executor, answer);
  _directory->update_group(actor_of(asking), group.id, std::move(change), expected, kStepDeadline, executor,
                           [answer](Outcome<directory::Group> changed) { answer->finish(result_of(changed)); });
}

void Writes::_members_of(std::vector<std::string> dns, Executor executor, std::function<void(std::optional<std::vector<std::string>>)> then) const {
  auto self = shared_from_this();
  auto names = std::make_shared<std::vector<std::string>>(std::move(dns));
  auto ids = std::make_shared<std::vector<std::string>>();
  auto missing = std::make_shared<bool>(false);
  in_turn<std::string>(
      names, 0,
      [=](const std::string& text, std::function<void()> next) {
        const auto dn = parse_dn(text);
        const auto place = dn ? self->_tree->locate(*dn) : Place{};
        if (*missing || (place.kind != Place::Kind::person && place.kind != Place::Kind::service)) {
          *missing = true;
          return next();
        }
        self->_directory->user_by_name(place.name, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
          const auto wanted = place.kind == Place::Kind::service ? directory::Kind::service : directory::Kind::person;
          if (!user.ok() || !user.value || user.value->kind != wanted) {
            *missing = true;
          } else {
            ids->push_back(user.value->id);
          }
          next();
        });
      },
      [=] { then(*missing ? std::nullopt : std::optional<std::vector<std::string>>(*ids)); });
}

void Writes::_modify_members(const Asking& asking, const directory::Group& group, const ModifyRequest& request, Executor executor,
                             std::shared_ptr<Completion<Result>> answer) {
  auto self = shared_from_this();
  const auto actor = actor_of(asking);
  const auto group_id = group.id;
  // Every value in the request, resolved first, so one that names nobody changes nothing.
  std::vector<std::string> all;
  for (const auto& change : request.changes) all.insert(all.end(), change.attribute.values.begin(), change.attribute.values.end());
  auto changes = std::make_shared<std::vector<Change>>(request.changes);
  _members_of(all, executor, [=](std::optional<std::vector<std::string>> resolved) {
    if (!resolved) return answer->finish(refused(ResultCode::no_such_object, "a member named is not in the tree"));
    self->_directory->members(group_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> current) {
      if (!current.ok()) return answer->finish(result_of(current));
      struct Step {
        bool add;
        std::string user_id;
      };
      auto steps = std::make_shared<std::vector<Step>>();
      std::set<std::string> members(current.value.begin(), current.value.end());
      std::size_t at = 0;
      for (const auto& change : *changes) {
        std::vector<std::string> values(resolved->begin() + static_cast<std::ptrdiff_t>(at),
                                        resolved->begin() + static_cast<std::ptrdiff_t>(at + change.attribute.values.size()));
        at += change.attribute.values.size();
        if (change.operation == ModifyOperation::add) {
          for (const auto& id : values) {
            if (members.insert(id).second) steps->push_back({true, id});
          }
        } else if (change.operation == ModifyOperation::remove && !values.empty()) {
          for (const auto& id : values) {
            if (members.erase(id) == 0) return answer->finish(refused(ResultCode::no_such_attribute, "that is not a member"));
            steps->push_back({false, id});
          }
        } else {
          // A replace, or a delete of every value.
          const std::set<std::string> wanted(values.begin(), values.end());
          for (const auto& id : std::vector<std::string>(members.begin(), members.end())) {
            if (wanted.count(id) == 0) {
              steps->push_back({false, id});
              members.erase(id);
            }
          }
          for (const auto& id : wanted) {
            if (members.insert(id).second) steps->push_back({true, id});
          }
        }
      }
      auto failure = std::make_shared<std::optional<Result>>();
      in_turn<Step>(
          steps, 0,
          [=](const Step& step, std::function<void()> next) {
            // The first failure is reported, with the rest not attempted.
            if (*failure) return next();
            const auto applied = [=](Outcome<> done) {
              if (!done.ok()) *failure = result_of(done);
              next();
            };
            if (step.add) {
              self->_directory->add_member(actor, group_id, step.user_id, kStepDeadline, executor, applied);
            } else {
              self->_directory->remove_member(actor, group_id, step.user_id, kStepDeadline, executor, applied);
            }
          },
          [=] { answer->finish(failure->value_or(Result{})); });
    });
  });
}

void Writes::add(Asking asking, AddRequest request, Executor executor, Done<Result> done) {
  auto answer = answering_result(executor, std::move(done));
  const auto dn = parse_dn(request.entry);
  if (!dn) return answer->finish(refused(ResultCode::invalid_dn_syntax, "not a distinguished name"));
  if (!may_write(asking.bound)) return answer->finish(refused(ResultCode::insufficient_access_rights, "that needs lugh:directory.write"));
  if (asking.assertion) return answer->finish(refused(ResultCode::assertion_failed, "there is no entry yet to assert anything of"));
  const auto place = _tree->locate(*dn);
  if (!place.leaf()) return answer->finish(refused(ResultCode::no_such_object, "only a person, a service or a group is added, under its container"));

  std::map<std::string, std::vector<std::string>> given;
  for (const auto& attribute : request.attributes) {
    const auto name = fold(attribute.type);
    if (name != "objectclass") {
      if (auto bad = forbidden_attribute(name)) return answer->finish(*bad);
    }
    auto& kept = given[name];
    kept.insert(kept.end(), attribute.values.begin(), attribute.values.end());
  }
  const auto one_of = [&](const std::string& name) -> std::optional<std::string> {
    const auto found = given.find(name);
    if (found == given.end() || found->second.size() != 1) return std::nullopt;
    return found->second.front();
  };
  const auto many = [&](const std::string& name) {
    const auto found = given.find(name);
    return found != given.end() && found->second.size() > 1;
  };
  const auto classes = given.count("objectclass") ? given.at("objectclass") : std::vector<std::string>{};
  const auto actor = actor_of(asking);

  if (place.kind == Place::Kind::group) {
    if (auto bad = classes_ok(classes, {"top", "groupofnames"}, "groupofnames")) return answer->finish(*bad);
    for (const auto& [name, values] : given) {
      if (name != "objectclass" && name != "cn" && name != "description" && name != "member") {
        return answer->finish(refused(ResultCode::no_such_attribute, "that attribute is not one this entry can have"));
      }
    }
    if (many("cn") || many("description")) return answer->finish(refused(ResultCode::constraint_violation, "each of these holds one value"));
    if (const auto cn = one_of("cn"); cn && fold(*cn) != place.name) {
      return answer->finish(refused(ResultCode::constraint_violation, "cn must be what the DN says"));
    }
    auto self = shared_from_this();
    const auto description = one_of("description").value_or("");
    const auto member_dns = given.count("member") ? given.at("member") : std::vector<std::string>{};
    return _members_of(member_dns, executor, [=](std::optional<std::vector<std::string>> members) {
      if (!members) return answer->finish(refused(ResultCode::no_such_object, "a member named is not in the tree"));
      self->_directory->create_group(actor, place.name, description, kStepDeadline, executor, [=](Outcome<directory::Group> made) {
        if (!made.ok()) return answer->finish(result_of(made));
        auto ids = std::make_shared<std::vector<std::string>>(*members);
        auto failure = std::make_shared<std::optional<Result>>();
        in_turn<std::string>(
            ids, 0,
            [=](const std::string& id, std::function<void()> next) {
              if (*failure) return next();
              self->_directory->add_member(actor, made.value.id, id, kStepDeadline, executor, [=](Outcome<> added) {
                if (!added.ok()) *failure = result_of(added);
                next();
              });
            },
            [=] { answer->finish(failure->value_or(Result{})); });
      });
    });
  }

  if (auto bad = classes_ok(classes, {"top", "person", "organizationalperson", "inetorgperson"}, "inetorgperson")) return answer->finish(*bad);
  for (const auto& [name, values] : given) {
    if (name != "objectclass" && name != "uid" && name != "cn" && name != "displayname" && name != "sn" && name != "givenname" && name != "mail") {
      return answer->finish(refused(ResultCode::no_such_attribute, "that attribute is not one this entry can have"));
    }
    if (name != "objectclass" && values.size() > 1) return answer->finish(refused(ResultCode::constraint_violation, "each of these holds one value"));
  }
  if (const auto uid = one_of("uid"); uid && fold(*uid) != place.name)
    return answer->finish(refused(ResultCode::constraint_violation, "uid must be what the DN says"));
  const bool person = place.kind == Place::Kind::person;
  const auto mail = one_of("mail").value_or("");
  if (person && mail.empty()) return answer->finish(refused(ResultCode::constraint_violation, "a person needs an address"));
  const auto shown = one_of("displayname").value_or(one_of("cn").value_or(""));
  if (shown.empty()) return answer->finish(refused(ResultCode::object_class_violation, "inetOrgPerson needs a cn"));
  if (!given.count("sn")) return answer->finish(refused(ResultCode::object_class_violation, "inetOrgPerson needs an sn"));

  directory::NewUser fresh{
      person ? directory::Kind::person : directory::Kind::service, place.name, mail, shown, one_of("givenname").value_or(""), one_of("sn").value_or("")};
  _directory->create_user(actor, std::move(fresh), kStepDeadline, executor, [answer](Outcome<directory::User> made) { answer->finish(result_of(made)); });
}

void Writes::remove(Asking asking, DeleteRequest request, Executor executor, Done<Result> done) {
  auto answer = answering_result(executor, std::move(done));
  auto self = shared_from_this();
  const auto actor = actor_of(asking);
  _checked(asking, request.entry, executor, answer, [=](Target target, std::optional<std::uint64_t> expected) {
    if (target.user) {
      const auto id = target.user->id;
      return self->_directory->remove_user(actor, id, expected, kStepDeadline, executor, [=](Outcome<> removed) {
        if (!removed.ok()) return answer->finish(result_of(removed));
        self->_sessions->end_user(actor, id, "", "the user was removed", kStepDeadline, executor, [answer](Outcome<std::size_t>) { answer->finish(Result{}); });
      });
    }
    if (target.group) {
      return self->_directory->remove_group(actor, target.group->id, expected, kStepDeadline, executor,
                                            [answer](Outcome<> removed) { answer->finish(result_of(removed)); });
    }
    answer->finish(refused(ResultCode::not_allowed_on_non_leaf, "the fixed tree does not change"));
  });
}

void Writes::rename(Asking asking, ModifyDnRequest request, Executor executor, Done<Result> done) {
  auto answer = answering_result(executor, std::move(done));
  if (request.new_superior) return answer->finish(refused(ResultCode::unwilling_to_perform, "an entry stays under its container"));
  if (!request.delete_old) return answer->finish(refused(ResultCode::unwilling_to_perform, "an entry has one name, so the old one goes"));
  const auto rdn = parse_dn(request.new_rdn);
  if (!rdn || rdn->rdns.size() != 1) return answer->finish(refused(ResultCode::invalid_dn_syntax, "not one component of a name"));
  const auto wanted = rdn->rdns[0];
  auto self = shared_from_this();
  const auto actor = actor_of(asking);
  _checked(asking, request.entry, executor, answer, [=](Target target, std::optional<std::uint64_t> expected) {
    if (target.user) {
      if (wanted.type != "uid") return answer->finish(refused(ResultCode::constraint_violation, "a user's name is its uid"));
      directory::UserChange change;
      change.name = wanted.value;
      return self->_directory->update_user(actor, target.user->id, std::move(change), expected, kStepDeadline, executor,
                                           [answer](Outcome<directory::User> changed) { answer->finish(result_of(changed)); });
    }
    if (target.group) {
      if (wanted.type != "cn") return answer->finish(refused(ResultCode::constraint_violation, "a group's name is its cn"));
      directory::GroupChange change;
      change.name = wanted.value;
      return self->_directory->update_group(actor, target.group->id, std::move(change), expected, kStepDeadline, executor,
                                            [answer](Outcome<directory::Group> changed) { answer->finish(result_of(changed)); });
    }
    answer->finish(refused(ResultCode::unwilling_to_perform, "the fixed tree does not change"));
  });
}

void Writes::password_modify(Asking asking, PasswordModify request, Executor executor, Done<Result> done) {
  auto answer = answering_result(executor, std::move(done));
  if (asking.bound.app_password) return answer->finish(refused(ResultCode::unwilling_to_perform, "an app password can never change the main one"));
  if (request.user) {
    const auto named = parse_dn(*request.user);
    const auto own = parse_dn(asking.bound.dn);
    if (!named || !own || normalised(*named) != normalised(*own))
      return answer->finish(refused(ResultCode::unwilling_to_perform, "only your own password, and only you"));
  }
  if (!request.new_password) return answer->finish(refused(ResultCode::unwilling_to_perform, "Lugh will not make up a password"));
  if (!request.old_password) return answer->finish(refused(ResultCode::unwilling_to_perform, "the old password is required"));

  auto self = shared_from_this();
  auto replacement = std::make_shared<Secret>(std::move(*request.new_password));
  auto old_password = std::make_shared<Secret>(std::move(*request.old_password));
  const auto actor = actor_of(asking);
  const auto user_id = asking.bound.caller.id;
  const auto address = asking.address;
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer->finish(result_of(user));
    if (!user.value) return answer->finish(refused(ResultCode::no_such_object, "no such entry"));
    self->_authenticator->password(user.value->name, std::move(*old_password), "ldap:" + address, kStepDeadline, executor, [=](authn::Step step) {
      if (step.kind == authn::Step::Kind::failed) return answer->finish(refused(ResultCode::unavailable, "the request could not be completed"));
      if (!password_alone_enough(step)) return answer->finish(refused(ResultCode::invalid_credentials, "invalid credentials"));
      self->_passwords->set(actor, *user.value, std::move(*replacement), kStepDeadline, executor, [=](Outcome<> set) {
        if (!set.ok()) return answer->finish(result_of(set));
        self->_sessions->end_user(actor, user_id, "", "the password was changed", kStepDeadline, executor,
                                  [answer](Outcome<std::size_t>) { answer->finish(Result{}); });
      });
    });
  });
}

}  // namespace lugh::ldap

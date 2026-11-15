//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>

#include "lugh/ldap/writes.h"
#include "lugh/scopes/scope.h"
#include "lugh/session/sessions.h"
#include "lugh/test/fixtures/authn_rig.h"

using namespace lugh::ldap;
using lugh::Executor;
using lugh::Outcome;
using lugh::directory::Group;
using lugh::directory::Kind;
using lugh::directory::User;

namespace {

constexpr const char* kBase = "dc=example,dc=com";
constexpr const char* kPassword = "correct horse battery";

std::string person_dn(const std::string& name) { return "uid=" + name + ",ou=people," + kBase; }
std::string service_dn(const std::string& name) { return "uid=" + name + ",ou=services," + kBase; }
std::string group_dn(const std::string& name) { return "cn=" + name + ",ou=groups," + kBase; }

Change change(ModifyOperation operation, const std::string& type, std::vector<std::string> values = {}) {
  return Change{operation, Attribute{type, std::move(values)}};
}
Change replace(const std::string& type, const std::string& value) { return change(ModifyOperation::replace, type, {value}); }

Filter version_is(std::uint64_t version) {
  Filter out;
  out.kind = Filter::Kind::equal;
  out.attribute = "lughentryversion";
  out.value = std::to_string(version);
  return out;
}

std::vector<Attribute> person_attributes(const std::string& name) {
  return {{"objectClass", {"top", "person", "organizationalPerson", "inetOrgPerson"}},
          {"uid", {name}},
          {"cn", {"Some One"}},
          {"sn", {"One"}},
          {"givenName", {"Some"}},
          {"mail", {name + "@example.com"}}};
}

class LdapWritesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Tree::Settings settings;
    settings.base_dn = kBase;
    tree = std::make_shared<Tree>(rig.directory, settings);
    sessions = std::make_shared<lugh::session::Sessions>(rig.store, rig.wall, rig.directory, rig.grants, rig.audit, lugh::session::Sessions::Settings{});
    ASSERT_TRUE(wait_for<lugh::Status>([&](Executor executor, auto done) { sessions->open(kTestDeadline, executor, done); }).ok);
    writes = std::make_shared<Writes>(tree, rig.directory, sessions, rig.passwords, rig.authenticator);
    alice = rig.enrolled("alice");
    staff = wait_for<Outcome<Group>>([&](Executor executor, auto done) {
              rig.directory->create_group(rig.admin, "staff", "The staff", kTestDeadline, executor, done);
            }).value;
  }

  Writes::Asking writer(std::optional<Filter> assertion = std::nullopt) {
    return as({lugh::scopes::kDirectoryWrite, lugh::scopes::kDirectoryRead}, std::move(assertion));
  }
  Writes::Asking as(std::vector<std::string> scopes, std::optional<Filter> assertion = std::nullopt) {
    Writes::Asking out;
    out.bound.dn = person_dn("alice");
    out.bound.caller = lugh::http::Caller{lugh::http::Caller::Kind::user, alice.id, std::move(scopes), "urn:lugh:acr:pwd"};
    out.address = "192.0.2.7";
    out.assertion = std::move(assertion);
    return out;
  }

  ResultCode modify(const Writes::Asking& asking, const std::string& object, std::vector<Change> changes) {
    return wait_for<Result>([&](Executor executor, auto done) { writes->modify(asking, {object, std::move(changes)}, executor, done); }).code;
  }
  ResultCode add(const Writes::Asking& asking, const std::string& entry, std::vector<Attribute> attributes) {
    return wait_for<Result>([&](Executor executor, auto done) { writes->add(asking, {entry, std::move(attributes)}, executor, done); }).code;
  }
  ResultCode remove(const Writes::Asking& asking, const std::string& entry) {
    return wait_for<Result>([&](Executor executor, auto done) { writes->remove(asking, {entry}, executor, done); }).code;
  }
  ResultCode rename(const Writes::Asking& asking, const std::string& entry, const std::string& rdn, bool delete_old = true,
                    std::optional<std::string> superior = std::nullopt) {
    return wait_for<Result>([&](Executor executor, auto done) { writes->rename(asking, {entry, rdn, delete_old, std::move(superior)}, executor, done); }).code;
  }
  ResultCode change_password(const Writes::Asking& asking, std::optional<std::string> user, std::optional<std::string> old_password,
                             std::optional<std::string> fresh) {
    PasswordModify request;
    request.user = std::move(user);
    if (old_password) request.old_password = lugh::text_secret(*old_password);
    if (fresh) request.new_password = lugh::text_secret(*fresh);
    return wait_for<Result>([&](Executor executor, auto done) { writes->password_modify(asking, std::move(request), executor, done); }).code;
  }

  User user_named(const std::string& name) {
    return *read_value<std::optional<User>>([&](Executor executor, auto done) { rig.directory->user_by_name(name, kTestDeadline, executor, done); });
  }
  bool has_user(const std::string& name) {
    return read_value<std::optional<User>>([&](Executor executor, auto done) { rig.directory->user_by_name(name, kTestDeadline, executor, done); }).has_value();
  }
  std::optional<Group> group_named(const std::string& name) {
    return read_value<std::optional<Group>>([&](Executor executor, auto done) { rig.directory->group_by_name(name, kTestDeadline, executor, done); });
  }
  std::vector<std::string> members(const std::string& name) {
    return read_value<std::vector<std::string>>(
        [&](Executor executor, auto done) { rig.directory->members(group_named(name)->id, kTestDeadline, executor, done); });
  }

  void password_policy() {
    ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                  rig.policies->global_set(rig.admin, lugh::authn::Assurance::pwd, kTestDeadline, executor, done);
                }).ok());
  }

  AuthnRig rig;
  std::shared_ptr<Tree> tree;
  std::shared_ptr<lugh::session::Sessions> sessions;
  std::shared_ptr<Writes> writes;
  User alice;
  Group staff;
};

}  // namespace

TEST_F(LdapWritesTest, ModifyingAUser) {
  ASSERT_EQ(modify(writer(), person_dn("alice"),
                   {replace("cn", "Alice Smith"), replace("givenName", "Alice"), replace("sn", "Smith"), replace("MAIL", "New@Example.com")}),
            ResultCode::success);
  auto now = user_named("alice");
  EXPECT_EQ(now.display_name, "Alice Smith");
  EXPECT_EQ(now.given_name, "Alice");
  EXPECT_EQ(now.family_name, "Smith");
  EXPECT_EQ(now.email, "new@example.com");
  EXPECT_TRUE(rig.audited("user.update"));

  EXPECT_EQ(modify(writer(), person_dn("alice"), {replace("displayName", "A")}), ResultCode::success);
  EXPECT_EQ(user_named("alice").display_name, "A") << "cn and displayName are one field";
  EXPECT_EQ(modify(writer(), person_dn("alice"), {change(ModifyOperation::remove, "sn"), change(ModifyOperation::remove, "givenName")}), ResultCode::success);
  EXPECT_EQ(user_named("alice").family_name, "");
}

// One update, so it succeeds or fails entire.
TEST_F(LdapWritesTest, AModifyFailsEntire) {
  rig.person("bob");
  EXPECT_EQ(modify(writer(), person_dn("alice"), {replace("cn", "Changed"), replace("mail", "bob@example.com")}), ResultCode::entry_already_exists);
  EXPECT_EQ(user_named("alice").display_name, "alice");
  EXPECT_EQ(modify(writer(), person_dn("alice"), {replace("cn", "Changed"), replace("uidNumber", "5")}), ResultCode::constraint_violation);
  EXPECT_EQ(user_named("alice").display_name, "alice");
}

TEST_F(LdapWritesTest, WhatAModifyRefuses) {
  const auto entry = person_dn("alice");
  EXPECT_EQ(modify(writer(), entry, {replace("userPassword", "x")}), ResultCode::unwilling_to_perform);
  for (const auto* name : {"objectClass", "memberOf", "uidNumber", "gidNumber", "entryUUID", "createTimestamp", "modifyTimestamp", "lughEntryVersion"}) {
    EXPECT_EQ(modify(writer(), entry, {replace(name, "x")}), ResultCode::constraint_violation) << name;
  }
  EXPECT_EQ(modify(writer(), entry, {replace("uid", "renamed")}), ResultCode::constraint_violation) << "that is a rename";
  EXPECT_EQ(modify(writer(), entry, {replace("seeAlso", "x")}), ResultCode::no_such_attribute);
  EXPECT_EQ(modify(writer(), entry, {change(ModifyOperation::add, "givenName", {"x"})}), ResultCode::unwilling_to_perform);
  EXPECT_EQ(modify(writer(), entry, {change(ModifyOperation::replace, "cn", {"a", "b"})}), ResultCode::constraint_violation);
  EXPECT_EQ(modify(writer(), entry, {change(ModifyOperation::remove, "cn")}), ResultCode::constraint_violation);
  EXPECT_EQ(modify(writer(), entry, {change(ModifyOperation::remove, "mail")}), ResultCode::constraint_violation) << "a person must keep one";
  EXPECT_EQ(modify(writer(), entry, {replace("mail", "not an address")}), ResultCode::constraint_violation);
  EXPECT_EQ(modify(writer(), kBase, {replace("o", "x")}), ResultCode::unwilling_to_perform);
  EXPECT_EQ(modify(writer(), person_dn("nobody"), {replace("cn", "x")}), ResultCode::no_such_object);
  EXPECT_EQ(modify(writer(), "not a dn", {replace("cn", "x")}), ResultCode::invalid_dn_syntax);
}

TEST_F(LdapWritesTest, AServiceMayHaveNoAddress) {
  ASSERT_EQ(add(writer(), service_dn("bot"),
                {{"objectClass", {"top", "person", "organizationalPerson", "inetOrgPerson"}}, {"cn", {"Bot"}}, {"sn", {"Bot"}}, {"mail", {"bot@example.com"}}}),
            ResultCode::success);
  EXPECT_EQ(modify(writer(), service_dn("bot"), {change(ModifyOperation::remove, "mail")}), ResultCode::success);
  EXPECT_EQ(user_named("bot").email, "");
}

TEST_F(LdapWritesTest, TheRights) {
  rig.person("bob");
  // Reads but does not write.
  const auto reader = as({lugh::scopes::kDirectoryRead});
  EXPECT_EQ(modify(reader, person_dn("bob"), {replace("cn", "x")}), ResultCode::insufficient_access_rights);
  EXPECT_EQ(remove(reader, person_dn("bob")), ResultCode::insufficient_access_rights);
  EXPECT_EQ(rename(reader, person_dn("bob"), "uid=robert"), ResultCode::insufficient_access_rights);
  EXPECT_EQ(add(reader, person_dn("new"), person_attributes("new")), ResultCode::insufficient_access_rights);

  // Reads nothing: what may not be seen is not there; its own entry is, and still may not be written.
  const auto nobody = as({});
  EXPECT_EQ(modify(nobody, person_dn("bob"), {replace("cn", "x")}), ResultCode::no_such_object);
  EXPECT_EQ(remove(nobody, person_dn("bob")), ResultCode::no_such_object);
  EXPECT_EQ(modify(nobody, person_dn("alice"), {replace("cn", "x")}), ResultCode::insufficient_access_rights);
  EXPECT_EQ(user_named("bob").display_name, "bob");
  EXPECT_TRUE(has_user("bob"));
}

// RFC 4528, and the API's If-Match by another name.
TEST_F(LdapWritesTest, TheAssertionControl) {
  const auto version = user_named("alice").version;
  EXPECT_EQ(modify(writer(version_is(version + 1)), person_dn("alice"), {replace("cn", "Stale")}), ResultCode::assertion_failed);
  EXPECT_EQ(user_named("alice").display_name, "alice");
  EXPECT_EQ(modify(writer(version_is(version)), person_dn("alice"), {replace("cn", "Fresh")}), ResultCode::success);
  EXPECT_EQ(user_named("alice").display_name, "Fresh");
  // The version just used is stale now.
  EXPECT_EQ(modify(writer(version_is(version)), person_dn("alice"), {replace("cn", "Again")}), ResultCode::assertion_failed);

  EXPECT_EQ(remove(writer(version_is(version)), person_dn("alice")), ResultCode::assertion_failed);
  EXPECT_TRUE(has_user("alice"));
  EXPECT_EQ(rename(writer(version_is(version)), person_dn("alice"), "uid=alicia"), ResultCode::assertion_failed);
  EXPECT_TRUE(has_user("alice"));

  // Any filter will do as an assertion.
  Filter is_alice;
  is_alice.kind = Filter::Kind::equal;
  is_alice.attribute = "uid";
  is_alice.value = "alice";
  EXPECT_EQ(modify(writer(is_alice), person_dn("alice"), {replace("cn", "Filtered")}), ResultCode::success);
  is_alice.value = "bob";
  EXPECT_EQ(modify(writer(is_alice), person_dn("alice"), {replace("cn", "No")}), ResultCode::assertion_failed);

  // Nothing yet to assert anything of.
  EXPECT_EQ(add(writer(version_is(1)), person_dn("new"), person_attributes("new")), ResultCode::assertion_failed);

  // And for a group's.
  const auto group_version = group_named("staff")->version;
  EXPECT_EQ(modify(writer(version_is(group_version + 1)), group_dn("staff"), {replace("description", "x")}), ResultCode::assertion_failed);
  EXPECT_EQ(modify(writer(version_is(group_version)), group_dn("staff"), {replace("description", "x")}), ResultCode::success);
}

TEST_F(LdapWritesTest, ModifyingAGroup) {
  EXPECT_EQ(modify(writer(), group_dn("staff"), {replace("description", "Everyone")}), ResultCode::success);
  EXPECT_EQ(group_named("staff")->description, "Everyone");
  EXPECT_EQ(modify(writer(), group_dn("staff"), {change(ModifyOperation::remove, "description")}), ResultCode::success);
  EXPECT_EQ(group_named("staff")->description, "");
  EXPECT_EQ(modify(writer(), group_dn("staff"), {replace("cn", "x")}), ResultCode::constraint_violation) << "that is a rename";
  EXPECT_EQ(modify(writer(), group_dn("staff"), {replace("mail", "x")}), ResultCode::no_such_attribute);
  EXPECT_EQ(modify(writer(), group_dn("staff"), {replace("gidNumber", "5")}), ResultCode::constraint_violation);
}

TEST_F(LdapWritesTest, MembersAddDeleteAndReplace) {
  const auto bob = rig.person("bob");
  const auto carol = rig.person("carol");
  const auto group = group_dn("staff");
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::add, "member", {person_dn("alice"), person_dn("BOB")})}), ResultCode::success);
  auto now = members("staff");
  std::sort(now.begin(), now.end());
  auto expected = std::vector<std::string>{alice.id, bob.id};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(now, expected);

  // Already in it changes nothing.
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::add, "member", {person_dn("alice")})}), ResultCode::success);
  EXPECT_EQ(members("staff").size(), 2u);

  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::remove, "member", {person_dn("alice")})}), ResultCode::success);
  EXPECT_EQ(members("staff"), (std::vector<std::string>{bob.id}));
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::remove, "member", {person_dn("alice")})}), ResultCode::no_such_attribute) << "not in it";

  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::replace, "member", {person_dn("carol")})}), ResultCode::success);
  EXPECT_EQ(members("staff"), (std::vector<std::string>{carol.id}));

  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::remove, "member")}), ResultCode::success);
  EXPECT_TRUE(members("staff").empty()) << "a delete with no values is all of them";
}

TEST_F(LdapWritesTest, WhatAMemberChangeRefuses) {
  const auto group = group_dn("staff");
  // One that names nobody changes nothing, even of the good ones before it.
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::add, "member", {person_dn("alice"), person_dn("nobody")})}), ResultCode::no_such_object);
  EXPECT_TRUE(members("staff").empty());
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::add, "member", {group_dn("staff")})}), ResultCode::no_such_object) << "a group is not a member";
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::add, "member", {"not a dn"})}), ResultCode::no_such_object);
  EXPECT_EQ(modify(writer(), group, {change(ModifyOperation::add, "member", {service_dn("alice")})}), ResultCode::no_such_object)
      << "under the wrong container";
  // Attributes or members, never both.
  EXPECT_EQ(modify(writer(), group, {replace("description", "x"), change(ModifyOperation::add, "member", {person_dn("alice")})}),
            ResultCode::unwilling_to_perform);
  EXPECT_EQ(group_named("staff")->description, "The staff");
  EXPECT_TRUE(members("staff").empty());
}

TEST_F(LdapWritesTest, AddingAPerson) {
  ASSERT_EQ(add(writer(), person_dn("New"), person_attributes("new")), ResultCode::success);
  const auto made = user_named("new");
  EXPECT_EQ(made.kind, Kind::person);
  EXPECT_FALSE(made.enrolled) << "as one made by the API";
  EXPECT_EQ(made.display_name, "Some One");
  EXPECT_EQ(made.given_name, "Some");
  EXPECT_EQ(made.family_name, "One");
  EXPECT_EQ(made.email, "new@example.com");
  EXPECT_EQ(add(writer(), person_dn("new"), person_attributes("new")), ResultCode::entry_already_exists);
}

TEST_F(LdapWritesTest, AddingAServiceIsEnrolledAtOnce) {
  ASSERT_EQ(add(writer(), service_dn("bot"), {{"objectClass", {"inetOrgPerson"}}, {"cn", {"Bot"}}, {"sn", {"Bot"}}}), ResultCode::success);
  const auto made = user_named("bot");
  EXPECT_EQ(made.kind, Kind::service);
  EXPECT_TRUE(made.enrolled);
}

TEST_F(LdapWritesTest, WhatAnAddRefuses) {
  auto with = [&](const std::string& type, std::vector<std::string> values) {
    auto out = person_attributes("new");
    out.push_back({type, std::move(values)});
    return out;
  };
  const auto entry = person_dn("new");
  EXPECT_EQ(add(writer(), entry, with("userPassword", {"secret"})), ResultCode::unwilling_to_perform);
  EXPECT_EQ(add(writer(), entry, with("uidNumber", {"5"})), ResultCode::constraint_violation);
  EXPECT_EQ(add(writer(), entry, with("seeAlso", {"x"})), ResultCode::no_such_attribute);

  auto other_class = person_attributes("new");
  other_class[0].values.push_back("posixAccount");
  EXPECT_EQ(add(writer(), entry, other_class), ResultCode::object_class_violation);
  auto no_class = person_attributes("new");
  no_class.erase(no_class.begin());
  EXPECT_EQ(add(writer(), entry, no_class), ResultCode::object_class_violation);

  auto no_sn = person_attributes("new");
  no_sn.erase(std::remove_if(no_sn.begin(), no_sn.end(), [](const Attribute& one) { return one.type == "sn"; }), no_sn.end());
  EXPECT_EQ(add(writer(), entry, no_sn), ResultCode::object_class_violation);
  auto no_cn = person_attributes("new");
  no_cn.erase(std::remove_if(no_cn.begin(), no_cn.end(), [](const Attribute& one) { return one.type == "cn"; }), no_cn.end());
  EXPECT_EQ(add(writer(), entry, no_cn), ResultCode::object_class_violation);
  auto no_mail = person_attributes("new");
  no_mail.erase(std::remove_if(no_mail.begin(), no_mail.end(), [](const Attribute& one) { return one.type == "mail"; }), no_mail.end());
  EXPECT_EQ(add(writer(), entry, no_mail), ResultCode::constraint_violation) << "a person needs one";

  auto wrong_uid = person_attributes("other");
  EXPECT_EQ(add(writer(), entry, wrong_uid), ResultCode::constraint_violation) << "uid must be what the DN says";
  auto two_mails = person_attributes("new");
  two_mails.back().values.push_back("second@example.com");
  EXPECT_EQ(add(writer(), entry, two_mails), ResultCode::constraint_violation);

  // Only under its container.
  EXPECT_EQ(add(writer(), kBase, person_attributes("new")), ResultCode::no_such_object);
  EXPECT_EQ(add(writer(), std::string("ou=people,") + kBase, person_attributes("new")), ResultCode::no_such_object);
  EXPECT_EQ(add(writer(), std::string("uid=new,") + kBase, person_attributes("new")), ResultCode::no_such_object);
  EXPECT_EQ(add(writer(), "uid=new,ou=people,dc=other", person_attributes("new")), ResultCode::no_such_object);
  EXPECT_EQ(add(writer(), "not a dn", person_attributes("new")), ResultCode::invalid_dn_syntax);
  EXPECT_FALSE(has_user("new"));
}

TEST_F(LdapWritesTest, AddingAGroup) {
  ASSERT_EQ(
      add(writer(), group_dn("ops"), {{"objectClass", {"top", "groupOfNames"}}, {"cn", {"ops"}}, {"description", {"Ops"}}, {"member", {person_dn("alice")}}}),
      ResultCode::success);
  EXPECT_EQ(group_named("ops")->description, "Ops");
  EXPECT_EQ(members("ops"), (std::vector<std::string>{alice.id}));

  EXPECT_EQ(add(writer(), group_dn("ops"), {{"objectClass", {"groupOfNames"}}}), ResultCode::entry_already_exists);
  EXPECT_EQ(add(writer(), group_dn("bad"), {{"objectClass", {"groupOfNames"}}, {"member", {person_dn("nobody")}}}), ResultCode::no_such_object);
  EXPECT_FALSE(group_named("bad")) << "made only once its members are known";
  EXPECT_EQ(add(writer(), group_dn("bad"), {{"objectClass", {"inetOrgPerson"}}}), ResultCode::object_class_violation);
  EXPECT_EQ(add(writer(), group_dn("bad"), {{"objectClass", {"groupOfNames"}}, {"mail", {"x"}}}), ResultCode::no_such_attribute);
  EXPECT_EQ(add(writer(), group_dn("bad"), {{"objectClass", {"groupOfNames"}}, {"cn", {"other"}}}), ResultCode::constraint_violation);
}

TEST_F(LdapWritesTest, DeletingAUserTakesEverythingWithThem) {
  const auto bob = rig.enrolled("bob");
  ASSERT_TRUE(
      wait_for<Outcome<>>([&](Executor executor, auto done) { rig.directory->add_member(rig.admin, staff.id, bob.id, kTestDeadline, executor, done); }).ok());
  const auto session = wait_for<Outcome<lugh::session::Sessions::Created>>(
      [&](Executor executor, auto done) { sessions->create(rig.admin, bob.id, lugh::authn::Assurance::mfa, {"pwd"}, kTestDeadline, executor, done); });
  ASSERT_TRUE(session.ok());

  ASSERT_EQ(remove(writer(), person_dn("bob")), ResultCode::success);
  EXPECT_FALSE(has_user("bob"));
  EXPECT_TRUE(members("staff").empty());
  const auto factors =
      read_value<std::vector<lugh::authn::FactorInfo>>([&](Executor executor, auto done) { rig.factors->list(bob.id, kTestDeadline, executor, done); });
  EXPECT_TRUE(factors.empty());
  EXPECT_TRUE(sessions->of_user(bob.id).empty()) << "at once";
  EXPECT_EQ(remove(writer(), person_dn("bob")), ResultCode::no_such_object);
}

TEST_F(LdapWritesTest, DeletingAGroupAndWhatCannotBeDeleted) {
  ASSERT_EQ(remove(writer(), group_dn("staff")), ResultCode::success);
  EXPECT_FALSE(group_named("staff"));
  EXPECT_EQ(remove(writer(), kBase), ResultCode::not_allowed_on_non_leaf);
  EXPECT_EQ(remove(writer(), std::string("ou=people,") + kBase), ResultCode::not_allowed_on_non_leaf);
}

TEST_F(LdapWritesTest, Renaming) {
  ASSERT_EQ(rename(writer(), person_dn("alice"), "uid=alicia"), ResultCode::success);
  EXPECT_FALSE(has_user("alice"));
  EXPECT_EQ(user_named("alicia").id, alice.id);
  ASSERT_EQ(rename(writer(), group_dn("staff"), "cn=team"), ResultCode::success);
  EXPECT_EQ(group_named("team")->id, staff.id);

  rig.person("bob");
  EXPECT_EQ(rename(writer(), person_dn("bob"), "uid=alicia"), ResultCode::entry_already_exists);
  EXPECT_EQ(rename(writer(), person_dn("bob"), "cn=bobby"), ResultCode::constraint_violation);
  EXPECT_EQ(rename(writer(), group_dn("team"), "uid=x"), ResultCode::constraint_violation);
  EXPECT_EQ(rename(writer(), person_dn("bob"), "uid=robert", true, std::string("ou=services,") + kBase), ResultCode::unwilling_to_perform) << "newSuperior";
  EXPECT_EQ(rename(writer(), person_dn("bob"), "uid=robert", false), ResultCode::unwilling_to_perform);
  EXPECT_EQ(rename(writer(), person_dn("bob"), "not an rdn"), ResultCode::invalid_dn_syntax);
  EXPECT_EQ(rename(writer(), person_dn("bob"), "uid=a,ou=b"), ResultCode::invalid_dn_syntax);
  EXPECT_EQ(rename(writer(), person_dn("bob"), "uid=not a valid name!"), ResultCode::constraint_violation);
  EXPECT_EQ(rename(writer(), kBase, "dc=other"), ResultCode::unwilling_to_perform);
  EXPECT_EQ(rename(writer(), person_dn("nobody"), "uid=x"), ResultCode::no_such_object);
}

TEST_F(LdapWritesTest, WritesAreAuditedAsTheBoundUserFromLdap) {
  ASSERT_EQ(modify(writer(), person_dn("alice"), {replace("cn", "Changed")}), ResultCode::success);
  bool found = false;
  for (const auto& entry : audit_entries(rig.audit, 1, 100000)) {
    if (entry.event.action == "user.update" && entry.event.actor == alice.id && entry.event.source == "ldap:192.0.2.7") found = true;
  }
  EXPECT_TRUE(found);
}

// RFC 3062, TODO/2026-11-04-ldap.md.
TEST_F(LdapWritesTest, ChangingYourOwnPassword) {
  password_policy();
  const auto session = wait_for<Outcome<lugh::session::Sessions::Created>>(
      [&](Executor executor, auto done) { sessions->create(rig.admin, alice.id, lugh::authn::Assurance::pwd, {"pwd"}, kTestDeadline, executor, done); });
  ASSERT_TRUE(session.ok());
  const std::string fresh = "a much better passphrase";
  ASSERT_EQ(change_password(as({}), std::nullopt, kPassword, fresh), ResultCode::success);
  EXPECT_TRUE(sessions->of_user(alice.id).empty()) << "every session of theirs ends";

  const auto with = [&](const std::string& password) {
    return wait_for<lugh::authn::Step>(
        [&](Executor executor, auto done) { rig.authenticator->password("alice", lugh::text_secret(password), "192.0.2.8", kTestDeadline, executor, done); });
  };
  EXPECT_EQ(with(kPassword).kind, lugh::authn::Step::Kind::refused);
  EXPECT_EQ(with(fresh).kind, lugh::authn::Step::Kind::next);

  // Naming yourself is the same as not naming anyone.
  EXPECT_EQ(change_password(as({}), person_dn("ALICE"), fresh, std::string(kPassword) + " again"), ResultCode::success);
}

TEST_F(LdapWritesTest, WhatPasswordModifyRefuses) {
  password_policy();
  const std::string fresh = "a much better passphrase";
  EXPECT_EQ(change_password(as({}), std::nullopt, "not it", fresh), ResultCode::invalid_credentials);
  EXPECT_EQ(change_password(as({}), std::nullopt, std::nullopt, fresh), ResultCode::unwilling_to_perform) << "the old one is required";
  EXPECT_EQ(change_password(as({}), std::nullopt, kPassword, std::nullopt), ResultCode::unwilling_to_perform) << "Lugh will not make one up";
  EXPECT_EQ(change_password(as({}), std::nullopt, kPassword, "short"), ResultCode::constraint_violation) << "the rules are the same";

  // Not someone else's, whatever the caller holds.
  rig.enrolled("bob");
  EXPECT_EQ(change_password(writer(), person_dn("bob"), kPassword, fresh), ResultCode::unwilling_to_perform);
  EXPECT_EQ(change_password(writer(), "not a dn", kPassword, fresh), ResultCode::unwilling_to_perform);

  // Never from an app password.
  auto through_app_password = as({lugh::scopes::kDirectoryWrite});
  through_app_password.bound.app_password = "an id";
  EXPECT_EQ(change_password(through_app_password, std::nullopt, kPassword, fresh), ResultCode::unwilling_to_perform);
}

// Guessing the old password counts as guessing a password.
TEST_F(LdapWritesTest, PasswordModifyHasTheBackOff) {
  password_policy();
  lugh::authn::Authenticator::Settings defaults;
  for (std::uint32_t i = 0; i < defaults.account.free_failures + 1; ++i) {
    ASSERT_EQ(change_password(as({}), std::nullopt, "not it", "a much better passphrase"), ResultCode::invalid_credentials);
  }
  EXPECT_EQ(change_password(as({}), std::nullopt, kPassword, "a much better passphrase"), ResultCode::invalid_credentials) << "right, and still waiting";
  rig.advance(std::chrono::hours(2));
  EXPECT_EQ(change_password(as({}), std::nullopt, kPassword, "a much better passphrase"), ResultCode::success);
}

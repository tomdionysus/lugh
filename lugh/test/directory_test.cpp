//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/directory/directory.h"

#include <gtest/gtest.h>

#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using namespace lugh::directory;

namespace {

class RecordingDependent : public Dependent {
 public:
  lugh::Task<lugh::Status> forget(lugh::audit::Actor, std::string user_id) override {
    forgotten.push_back(user_id);
    co_return lugh::Status::success();
  }
  std::vector<std::string> forgotten;
};

class DirectoryTest : public ::testing::Test {
 protected:
  AuthnRig rig;
  Directory& directory = *rig.directory;
  lugh::audit::Actor admin = rig.admin;
};

}  // namespace

TEST_F(DirectoryTest, APersonStartsNotEnrolled) {
  const auto made = run(directory.create_user(admin, {Kind::person, "Alice", "Alice@Example.com", "Alice Smith"}));
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.id.size(), 32u);
  EXPECT_EQ(made.value.version, 1u);
  EXPECT_EQ(made.value.name, "alice");
  EXPECT_EQ(made.value.email, "alice@example.com");
  EXPECT_FALSE(made.value.enrolled);
  EXPECT_FALSE(made.value.disabled);
  EXPECT_EQ(made.value.created, 1792281600u);

  const auto found = run(directory.user(made.value.id));
  ASSERT_TRUE(found);
  EXPECT_EQ(found->display_name, "Alice Smith");
  EXPECT_EQ(run(directory.user_by_name("ALICE"))->id, made.value.id);
  EXPECT_EQ(run(directory.user_by_email("alice@EXAMPLE.com"))->id, made.value.id);
  EXPECT_EQ(run(directory.user_by_login("alice@example.com"))->id, made.value.id);
  EXPECT_EQ(run(directory.user_by_login("alice"))->id, made.value.id);
  EXPECT_TRUE(rig.audited("user.create"));
}

TEST_F(DirectoryTest, AServiceIsEnrolledAndNeedsNoAddress) {
  const auto made = run(directory.create_user(admin, {Kind::service, "backup", "", "Nightly backup"}));
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_TRUE(made.value.enrolled);
  EXPECT_EQ(made.value.kind, Kind::service);
}

TEST_F(DirectoryTest, WhatCannotBeStoredIsRefused) {
  EXPECT_EQ(run(directory.create_user(admin, {Kind::person, "al ice", "a@example.com", ""})).fault, Fault::invalid);
  EXPECT_EQ(run(directory.create_user(admin, {Kind::person, "alice", "not an address", ""})).fault, Fault::invalid);
  EXPECT_EQ(run(directory.create_user(admin, {Kind::person, "alice", "a@example.com", "bell\x07"})).fault, Fault::invalid);
  EXPECT_TRUE(run(directory.users()).empty());
}

TEST_F(DirectoryTest, NamesAndAddressesAreUniqueWhateverTheCase) {
  ASSERT_TRUE(run(directory.create_user(admin, {Kind::person, "alice", "alice@example.com", ""})).ok());
  EXPECT_EQ(run(directory.create_user(admin, {Kind::person, "ALICE", "other@example.com", ""})).fault, Fault::duplicate);
  EXPECT_EQ(run(directory.create_user(admin, {Kind::person, "alice2", "ALICE@example.com", ""})).fault, Fault::duplicate);
  EXPECT_EQ(run(directory.users()).size(), 1u);
}

TEST_F(DirectoryTest, UpdatesAreChangedFieldsOnlyAndCheckTheVersion) {
  const auto alice = rig.person("alice");
  rig.person("bob");

  const auto renamed = run(directory.update_user(admin, alice.id, {"Alicia", std::nullopt, std::nullopt}, alice.version));
  ASSERT_TRUE(renamed.ok()) << renamed.message;
  EXPECT_EQ(renamed.value.name, "alicia");
  EXPECT_EQ(renamed.value.email, "alice@example.com");
  EXPECT_EQ(renamed.value.version, 2u);
  EXPECT_FALSE(run(directory.user_by_name("alice")));

  // A writer holding the old version loses.
  EXPECT_EQ(run(directory.update_user(admin, alice.id, {std::nullopt, std::nullopt, "A"}, alice.version)).fault, Fault::conflict);
  EXPECT_EQ(run(directory.update_user(admin, alice.id, {"bob", std::nullopt, std::nullopt})).fault, Fault::duplicate);
  EXPECT_EQ(run(directory.update_user(admin, alice.id, {std::nullopt, "not an address", std::nullopt})).fault, Fault::invalid);
  EXPECT_EQ(run(directory.update_user(admin, "nobody", {})).fault, Fault::not_found);

  // Nothing changed is no write.
  EXPECT_EQ(run(directory.update_user(admin, alice.id, {"alicia", std::nullopt, std::nullopt})).value.version, 2u);
}

TEST_F(DirectoryTest, DisablingIsAuditedAndReversible) {
  const auto alice = rig.person("alice");
  const auto off = run(directory.disable_user(admin, alice.id, true));
  ASSERT_TRUE(off.ok());
  EXPECT_TRUE(off.value.disabled);
  EXPECT_TRUE(rig.audited("user.disable"));
  const auto on = run(directory.disable_user(admin, alice.id, false));
  EXPECT_FALSE(on.value.disabled);
  EXPECT_TRUE(rig.audited("user.enable"));
}

TEST_F(DirectoryTest, RemovalTakesEverythingOfTheirsAndFreesTheName) {
  auto dependent = std::make_shared<RecordingDependent>();
  directory.dependent_add(dependent);
  const auto alice = rig.person("alice");
  const auto group = run(directory.create_group(admin, "staff", "")).value;
  ASSERT_TRUE(run(directory.add_member(admin, group.id, alice.id)).ok());

  ASSERT_TRUE(run(directory.remove_user(admin, alice.id)).ok());
  EXPECT_FALSE(run(directory.user(alice.id)));
  EXPECT_TRUE(run(directory.members(group.id)).empty());
  EXPECT_EQ(dependent->forgotten, std::vector<std::string>{alice.id});
  EXPECT_TRUE(rig.audited("user.remove"));

  // A new person may take the name, under a new ID.
  const auto again = rig.person("alice");
  EXPECT_NE(again.id, alice.id);
  EXPECT_EQ(run(directory.remove_user(admin, alice.id)).fault, Fault::not_found);
}

TEST_F(DirectoryTest, RemovalChecksTheVersion) {
  const auto alice = rig.person("alice");
  run(directory.disable_user(admin, alice.id, true));
  EXPECT_EQ(run(directory.remove_user(admin, alice.id, alice.version)).fault, Fault::conflict);
  EXPECT_TRUE(run(directory.user(alice.id)));
}

TEST_F(DirectoryTest, GroupsAndMembers) {
  const auto alice = rig.person("alice");
  const auto bob = rig.person("bob");
  const auto staff = run(directory.create_group(admin, "Staff", "Everyone"));
  ASSERT_TRUE(staff.ok());
  EXPECT_EQ(staff.value.name, "staff");
  EXPECT_EQ(run(directory.create_group(admin, "STAFF", "")).fault, Fault::duplicate);
  const auto admins = run(directory.create_group(admin, "admins", "")).value;

  ASSERT_TRUE(run(directory.add_member(admin, staff.value.id, alice.id)).ok());
  ASSERT_TRUE(run(directory.add_member(admin, staff.value.id, bob.id)).ok());
  ASSERT_TRUE(run(directory.add_member(admin, admins.id, alice.id)).ok());
  // Again: no second membership.
  ASSERT_TRUE(run(directory.add_member(admin, staff.value.id, alice.id)).ok());

  EXPECT_EQ(run(directory.members(staff.value.id)).size(), 2u);
  EXPECT_EQ(run(directory.groups_of(alice.id)).size(), 2u);
  EXPECT_EQ(run(directory.add_member(admin, "nothing", alice.id)).fault, Fault::not_found);
  EXPECT_EQ(run(directory.add_member(admin, staff.value.id, "nobody")).fault, Fault::not_found);

  ASSERT_TRUE(run(directory.remove_member(admin, staff.value.id, alice.id)).ok());
  EXPECT_EQ(run(directory.members(staff.value.id)), std::vector<std::string>{bob.id});
  EXPECT_EQ(run(directory.remove_member(admin, staff.value.id, alice.id)).fault, Fault::not_found);

  // A removal is final for its record, not for the person: they can join again.
  ASSERT_TRUE(run(directory.add_member(admin, staff.value.id, alice.id)).ok());
  EXPECT_EQ(run(directory.members(staff.value.id)).size(), 2u);

  ASSERT_TRUE(run(directory.remove_group(admin, staff.value.id)).ok());
  EXPECT_EQ(run(directory.groups_of(alice.id)), std::vector<std::string>{admins.id});
  EXPECT_FALSE(run(directory.group_by_name("staff")));
}

TEST_F(DirectoryTest, GroupUpdates) {
  const auto group = run(directory.create_group(admin, "staff", "")).value;
  run(directory.create_group(admin, "admins", ""));
  const auto changed = run(directory.update_group(admin, group.id, {"people", "Everyone here"}, group.version));
  ASSERT_TRUE(changed.ok());
  EXPECT_EQ(changed.value.name, "people");
  EXPECT_EQ(changed.value.description, "Everyone here");
  EXPECT_EQ(run(directory.update_group(admin, group.id, {"admins", std::nullopt})).fault, Fault::duplicate);
  EXPECT_EQ(run(directory.update_group(admin, group.id, {std::nullopt, "x"}, group.version)).fault, Fault::conflict);
}

TEST_F(DirectoryTest, EveryChangeNamesItsActor) {
  rig.person("alice");
  const auto entry = audit_entries(rig.audit, 1, 1).at(0);
  EXPECT_EQ(entry.event.actor, "admin");
  EXPECT_EQ(entry.event.source, "192.0.2.10");
}

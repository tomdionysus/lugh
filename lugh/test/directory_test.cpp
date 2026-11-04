//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/directory/directory.h"

#include <gtest/gtest.h>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

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
  std::shared_ptr<Directory>& directory = rig.directory;
  lugh::audit::Actor admin = rig.admin;
};

}  // namespace

TEST_F(DirectoryTest, APersonStartsNotEnrolled) {
  const auto made = wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
    directory->create_user(admin, {Kind::person, "Alice", "Alice@Example.com", "Alice Smith"}, kTestDeadline, executor, done);
  });
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.id.size(), 32u);
  EXPECT_EQ(made.value.version, 1u);
  EXPECT_EQ(made.value.name, "alice");
  EXPECT_EQ(made.value.email, "alice@example.com");
  EXPECT_FALSE(made.value.enrolled);
  EXPECT_FALSE(made.value.disabled);
  EXPECT_EQ(made.value.created, 1792281600u);

  const auto found = read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { directory->user(made.value.id, kTestDeadline, executor, done); });
  ASSERT_TRUE(found);
  EXPECT_EQ(found->display_name, "Alice Smith");
  EXPECT_EQ(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->user_by_name("ALICE", kTestDeadline, executor, done);
            })->id,
            made.value.id);
  EXPECT_EQ(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->user_by_email("alice@EXAMPLE.com", kTestDeadline, executor, done);
            })->id,
            made.value.id);
  EXPECT_EQ(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->user_by_login("alice@example.com", kTestDeadline, executor, done);
            })->id,
            made.value.id);
  EXPECT_EQ(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->user_by_login("alice", kTestDeadline, executor, done);
            })->id,
            made.value.id);
  EXPECT_TRUE(rig.audited("user.create"));
}

TEST_F(DirectoryTest, AServiceIsEnrolledAndNeedsNoAddress) {
  const auto made = wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
    directory->create_user(admin, {Kind::service, "backup", "", "Nightly backup"}, kTestDeadline, executor, done);
  });
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_TRUE(made.value.enrolled);
  EXPECT_EQ(made.value.kind, Kind::service);
}

TEST_F(DirectoryTest, WhatCannotBeStoredIsRefused) {
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->create_user(admin, {Kind::person, "al ice", "a@example.com", ""}, kTestDeadline, executor, done);
            }).fault,
            Fault::invalid);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->create_user(admin, {Kind::person, "alice", "not an address", ""}, kTestDeadline, executor, done);
            }).fault,
            Fault::invalid);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->create_user(admin, {Kind::person, "alice", "a@example.com", "bell\x07"}, kTestDeadline, executor, done);
            }).fault,
            Fault::invalid);
  EXPECT_TRUE(
      read_value<std::vector<lugh::directory::User>>([&](lugh::Executor executor, auto done) { directory->users(kTestDeadline, executor, done); }).empty());
}

TEST_F(DirectoryTest, NamesAndAddressesAreUniqueWhateverTheCase) {
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                directory->create_user(admin, {Kind::person, "alice", "alice@example.com", ""}, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->create_user(admin, {Kind::person, "ALICE", "other@example.com", ""}, kTestDeadline, executor, done);
            }).fault,
            Fault::duplicate);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->create_user(admin, {Kind::person, "alice2", "ALICE@example.com", ""}, kTestDeadline, executor, done);
            }).fault,
            Fault::duplicate);
  EXPECT_EQ(read_value<std::vector<lugh::directory::User>>([&](lugh::Executor executor, auto done) { directory->users(kTestDeadline, executor, done); }).size(),
            1u);
}

TEST_F(DirectoryTest, UpdatesAreChangedFieldsOnlyAndCheckTheVersion) {
  const auto alice = rig.person("alice");
  rig.person("bob");

  const auto renamed = wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
    directory->update_user(admin, alice.id, {"Alicia", std::nullopt, std::nullopt}, alice.version, kTestDeadline, executor, done);
  });
  ASSERT_TRUE(renamed.ok()) << renamed.message;
  EXPECT_EQ(renamed.value.name, "alicia");
  EXPECT_EQ(renamed.value.email, "alice@example.com");
  EXPECT_EQ(renamed.value.version, 2u);
  EXPECT_FALSE(read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { directory->user_by_name("alice", kTestDeadline, executor, done); }));

  // A writer holding the old version loses.
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->update_user(admin, alice.id, {std::nullopt, std::nullopt, "A"}, alice.version, kTestDeadline, executor, done);
            }).fault,
            Fault::conflict);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->update_user(admin, alice.id, {"bob", std::nullopt, std::nullopt}, std::nullopt, kTestDeadline, executor, done);
            }).fault,
            Fault::duplicate);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->update_user(admin, alice.id, {std::nullopt, "not an address", std::nullopt}, std::nullopt, kTestDeadline, executor, done);
            }).fault,
            Fault::invalid);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->update_user(admin, "nobody", {}, std::nullopt, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);

  // Nothing changed is no write.
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
              directory->update_user(admin, alice.id, {"alicia", std::nullopt, std::nullopt}, std::nullopt, kTestDeadline, executor, done);
            }).value.version,
            2u);
}

TEST_F(DirectoryTest, DisablingIsAuditedAndReversible) {
  const auto alice = rig.person("alice");
  const auto off = wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { directory->disable_user(admin, alice.id, true, std::nullopt, kTestDeadline, executor, done); });
  ASSERT_TRUE(off.ok());
  EXPECT_TRUE(off.value.disabled);
  EXPECT_TRUE(rig.audited("user.disable"));
  const auto on = wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { directory->disable_user(admin, alice.id, false, std::nullopt, kTestDeadline, executor, done); });
  EXPECT_FALSE(on.value.disabled);
  EXPECT_TRUE(rig.audited("user.enable"));
}

TEST_F(DirectoryTest, RemovalTakesEverythingOfTheirsAndFreesTheName) {
  auto dependent = std::make_shared<RecordingDependent>();
  directory->dependent_add(dependent);
  const auto alice = rig.person("alice");
  const auto group = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                       directory->create_group(admin, "staff", "", kTestDeadline, executor, done);
                     }).value;
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->add_member(admin, group.id, alice.id, kTestDeadline, executor, done);
              }).ok());

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->remove_user(admin, alice.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(
      read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) { directory->user(alice.id, kTestDeadline, executor, done); }));
  EXPECT_TRUE(
      read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) { directory->members(group.id, kTestDeadline, executor, done); }).empty());
  EXPECT_EQ(dependent->forgotten, std::vector<std::string>{alice.id});
  EXPECT_TRUE(rig.audited("user.remove"));

  // A new person may take the name, under a new ID.
  const auto again = rig.person("alice");
  EXPECT_NE(again.id, alice.id);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              directory->remove_user(admin, alice.id, std::nullopt, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
}

TEST_F(DirectoryTest, RemovalChecksTheVersion) {
  const auto alice = rig.person("alice");
  wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { directory->disable_user(admin, alice.id, true, std::nullopt, kTestDeadline, executor, done); });
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              directory->remove_user(admin, alice.id, alice.version, kTestDeadline, executor, done);
            }).fault,
            Fault::conflict);
  EXPECT_TRUE(
      read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) { directory->user(alice.id, kTestDeadline, executor, done); }));
}

TEST_F(DirectoryTest, GroupsAndMembers) {
  const auto alice = rig.person("alice");
  const auto bob = rig.person("bob");
  const auto staff = wait_for<lugh::Outcome<lugh::directory::Group>>(
      [&](lugh::Executor executor, auto done) { directory->create_group(admin, "Staff", "Everyone", kTestDeadline, executor, done); });
  ASSERT_TRUE(staff.ok());
  EXPECT_EQ(staff.value.name, "staff");
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
              directory->create_group(admin, "STAFF", "", kTestDeadline, executor, done);
            }).fault,
            Fault::duplicate);
  const auto admins = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                        directory->create_group(admin, "admins", "", kTestDeadline, executor, done);
                      }).value;

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->add_member(admin, staff.value.id, alice.id, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->add_member(admin, staff.value.id, bob.id, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->add_member(admin, admins.id, alice.id, kTestDeadline, executor, done);
              }).ok());
  // Again: no second membership.
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->add_member(admin, staff.value.id, alice.id, kTestDeadline, executor, done);
              }).ok());

  EXPECT_EQ(read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) {
              directory->members(staff.value.id, kTestDeadline, executor, done);
            }).size(),
            2u);
  EXPECT_EQ(
      read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) { directory->groups_of(alice.id, kTestDeadline, executor, done); }).size(),
      2u);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              directory->add_member(admin, "nothing", alice.id, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              directory->add_member(admin, staff.value.id, "nobody", kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->remove_member(admin, staff.value.id, alice.id, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(
      read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) { directory->members(staff.value.id, kTestDeadline, executor, done); }),
      std::vector<std::string>{bob.id});
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              directory->remove_member(admin, staff.value.id, alice.id, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);

  // A removal is final for its record, not for the person: they can join again.
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->add_member(admin, staff.value.id, alice.id, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) {
              directory->members(staff.value.id, kTestDeadline, executor, done);
            }).size(),
            2u);

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                directory->remove_group(admin, staff.value.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) { directory->groups_of(alice.id, kTestDeadline, executor, done); }),
            std::vector<std::string>{admins.id});
  EXPECT_FALSE(read_value<std::optional<lugh::directory::Group>>(
      [&](lugh::Executor executor, auto done) { directory->group_by_name("staff", kTestDeadline, executor, done); }));
}

TEST_F(DirectoryTest, GroupUpdates) {
  const auto group = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                       directory->create_group(admin, "staff", "", kTestDeadline, executor, done);
                     }).value;
  wait_for<lugh::Outcome<lugh::directory::Group>>(
      [&](lugh::Executor executor, auto done) { directory->create_group(admin, "admins", "", kTestDeadline, executor, done); });
  const auto changed = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
    directory->update_group(admin, group.id, {"people", "Everyone here"}, group.version, kTestDeadline, executor, done);
  });
  ASSERT_TRUE(changed.ok());
  EXPECT_EQ(changed.value.name, "people");
  EXPECT_EQ(changed.value.description, "Everyone here");
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
              directory->update_group(admin, group.id, {"admins", std::nullopt}, std::nullopt, kTestDeadline, executor, done);
            }).fault,
            Fault::duplicate);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
              directory->update_group(admin, group.id, {std::nullopt, "x"}, group.version, kTestDeadline, executor, done);
            }).fault,
            Fault::conflict);
}

TEST_F(DirectoryTest, EveryChangeNamesItsActor) {
  rig.person("alice");
  const auto entry = audit_entries(rig.audit, 1, 1).at(0);
  EXPECT_EQ(entry.event.actor, "admin");
  EXPECT_EQ(entry.event.source, "192.0.2.10");
}

namespace {

// A store whose reads take longer than any deadline the test gives: the answer arrives,
// late, after the caller has been told.
class SlowStore : public lugh::store::Store {
 public:
  explicit SlowStore(std::shared_ptr<lugh::store::Store> inner) : _inner(std::move(inner)) {}
  lugh::Task<std::optional<lugh::store::Record>> get(std::string table, std::string key) const override {
    co_await _pause();
    co_return co_await _inner->get(std::move(table), std::move(key));
  }
  lugh::Task<std::optional<lugh::store::Record>> find(std::string table, std::string index, std::string value) const override {
    co_await _pause();
    co_return co_await _inner->find(std::move(table), std::move(index), std::move(value));
  }
  lugh::Task<std::vector<lugh::store::Record>> list(std::string table) const override {
    co_await _pause();
    co_return co_await _inner->list(std::move(table));
  }
  lugh::Task<bool> removed(std::string table, std::string key) const override { co_return co_await _inner->removed(std::move(table), std::move(key)); }
  lugh::Task<lugh::store::Write> put(std::string table, std::string key, lugh::SecureBuffer value, std::optional<std::uint64_t> expected) override {
    co_return co_await _inner->put(std::move(table), std::move(key), std::move(value), expected);
  }
  lugh::Task<lugh::store::Write> remove(std::string table, std::string key, std::optional<std::uint64_t> expected) override {
    co_return co_await _inner->remove(std::move(table), std::move(key), expected);
  }

 private:
  static lugh::Task<void> _pause() {
    boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor, std::chrono::milliseconds(300));
    co_await timer.async_wait(boost::asio::use_awaitable);
  }
  std::shared_ptr<lugh::store::Store> _inner;
};

}  // namespace

// A read past its deadline is a failure, never "no such user": a timeout must not pass for
// absence. A write past its deadline says it may yet be made.
TEST_F(DirectoryTest, PastTheDeadlineIsAFailureNeverAbsence) {
  auto slow = std::make_shared<lugh::directory::Directory>(rig.logger, std::make_shared<SlowStore>(rig.store), rig.wall, rig.audit);
  const auto read = wait_for<lugh::Outcome<std::optional<lugh::directory::User>>>(
      [&](lugh::Executor executor, auto done) { slow->user_by_name("alice", std::chrono::milliseconds(20), executor, done); });
  EXPECT_EQ(read.fault, Fault::failed);
  EXPECT_NE(read.message.find("deadline"), std::string::npos) << read.message;

  const auto made = wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { slow->create_user(admin, {Kind::person, "alice", "", ""}, std::chrono::milliseconds(20), executor, done); });
  EXPECT_EQ(made.fault, Fault::failed);
  EXPECT_NE(made.message.find("may yet be made"), std::string::npos) << made.message;
}

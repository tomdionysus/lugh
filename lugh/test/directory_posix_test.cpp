//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <set>

#include "lugh/api/ldap_routes.h"
#include "lugh/directory/posix_numbers.h"
#include "lugh/ldap/operations.h"
#include "lugh/ldap/tree.h"
#include "lugh/scopes/scope.h"
#include "lugh/test/fixtures/api_rig.h"

using lugh::Executor;
using lugh::Outcome;
using lugh::directory::Group;
using lugh::directory::Kind;
using lugh::directory::Numbered;
using lugh::directory::PosixNumbers;
using lugh::directory::User;
using namespace lugh::ldap;

namespace {

class PosixTest : public ::testing::Test {
 protected:
  void numbered(PosixNumbers::Range users = {10000, 19999}, PosixNumbers::Range groups = {20000, 29999}) {
    rig.directory->numbers_set(std::make_shared<PosixNumbers>(rig.store, users, groups));
  }

  Outcome<User> person(const std::string& name) {
    return wait_for<Outcome<User>>([&](Executor executor, auto done) {
      rig.directory->create_user(rig.admin, {Kind::person, name, name + "@example.com", name, "", ""}, kTestDeadline, executor, done);
    });
  }
  Outcome<User> service(const std::string& name) {
    return wait_for<Outcome<User>>(
        [&](Executor executor, auto done) { rig.directory->create_user(rig.admin, {Kind::service, name, "", name, "", ""}, kTestDeadline, executor, done); });
  }
  Outcome<Group> group(const std::string& name) {
    return wait_for<Outcome<Group>>([&](Executor executor, auto done) { rig.directory->create_group(rig.admin, name, "", kTestDeadline, executor, done); });
  }
  Outcome<Numbered> allocate() {
    return wait_for<Outcome<Numbered>>([&](Executor executor, auto done) { rig.directory->allocate_numbers(rig.admin, kTestDeadline, executor, done); });
  }
  User read_user(const std::string& id) {
    return *read_value<std::optional<User>>([&](Executor executor, auto done) { rig.directory->user(id, kTestDeadline, executor, done); });
  }
  Group read_group(const std::string& id) {
    return *read_value<std::optional<Group>>([&](Executor executor, auto done) { rig.directory->group(id, kTestDeadline, executor, done); });
  }

  ApiRig rig;
};

}  // namespace

TEST_F(PosixTest, NotConfiguredNothingIsNumbered) {
  EXPECT_FALSE(person("alice").value.posix_number);
  EXPECT_FALSE(group("staff").value.posix_number);
  EXPECT_EQ(allocate().fault, lugh::Fault::refused);
}

TEST_F(PosixTest, NumberedWhenMade) {
  numbered();
  EXPECT_EQ(person("alice").value.posix_number, 10000u);
  EXPECT_EQ(person("bob").value.posix_number, 10001u);
  EXPECT_EQ(group("staff").value.posix_number, 20000u);
  EXPECT_EQ(group("ops").value.posix_number, 20001u);
  // Kept, as a read of the record shows.
  const auto carol = person("carol").value;
  EXPECT_EQ(read_user(carol.id).posix_number, 10002u);
}

// A service cannot have a posixAccount, so it spends no number.
TEST_F(PosixTest, AServiceHasNoNumber) {
  numbered();
  EXPECT_FALSE(service("bot").value.posix_number);
  EXPECT_EQ(person("alice").value.posix_number, 10000u);
}

// TODO/2026-11-04-ldap.md: a removed user's number dies with the tombstone.
TEST_F(PosixTest, ANumberIsNeverGivenAgain) {
  numbered();
  const auto alice = person("alice").value;
  ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                rig.directory->remove_user(rig.admin, alice.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  const auto again = person("alice").value;
  EXPECT_NE(again.id, alice.id);
  EXPECT_EQ(again.posix_number, 10001u);

  const auto staff = group("staff").value;
  ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                rig.directory->remove_group(rig.admin, staff.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(group("staff").value.posix_number, 20001u);
}

// One refused for its name still spends nothing a person would notice, and never a number twice.
TEST_F(PosixTest, ARefusedCreationSpendsNothing) {
  numbered();
  ASSERT_TRUE(person("alice").ok());
  EXPECT_EQ(person("alice").fault, lugh::Fault::duplicate);
  EXPECT_EQ(person("bob").value.posix_number, 10001u);
}

// A new node over the same store goes on from where the counter is.
TEST_F(PosixTest, TheCounterIsInTheStore) {
  numbered();
  ASSERT_EQ(person("alice").value.posix_number, 10000u);
  numbered();
  EXPECT_EQ(person("bob").value.posix_number, 10001u);
}

TEST_F(PosixTest, ManyAtOnceNeverShare) {
  numbered();
  const int count = 32;
  auto numbers = std::make_shared<PosixNumbers>(rig.store, PosixNumbers::Range{10000, 19999}, PosixNumbers::Range{20000, 29999});
  boost::asio::io_context io;
  std::vector<Outcome<std::uint32_t>> got(static_cast<std::size_t>(count));
  for (int i = 0; i < count; ++i) {
    numbers->next_user(io.get_executor(), [&got, i](Outcome<std::uint32_t> one) { got[static_cast<std::size_t>(i)] = std::move(one); });
  }
  io.run();
  std::set<std::uint32_t> seen;
  for (const auto& one : got) {
    ASSERT_TRUE(one.ok()) << one.message;
    EXPECT_TRUE(seen.insert(one.value).second) << one.value;
  }
  EXPECT_EQ(seen.size(), static_cast<std::size_t>(count));
}

TEST_F(PosixTest, ARangeUsedUp) {
  numbered({10000, 10001}, {20000, 20000});
  EXPECT_TRUE(person("a").ok());
  EXPECT_TRUE(person("b").ok());
  const auto third = person("c");
  EXPECT_EQ(third.fault, lugh::Fault::refused);
  EXPECT_FALSE(read_value<std::optional<User>>([&](Executor executor, auto done) { rig.directory->user_by_name("c", kTestDeadline, executor, done); }));
  EXPECT_TRUE(group("g").ok());
  EXPECT_EQ(group("h").fault, lugh::Fault::refused);

  // A wider range goes on from there.
  numbered({10000, 10002}, {20000, 20001});
  EXPECT_EQ(person("c").value.posix_number, 10002u);
}

// Those made before a range was configured, in creation order, in one audited pass.
TEST_F(PosixTest, TheBackfill) {
  const auto alice = person("alice").value;
  rig.advance(std::chrono::seconds(1));
  const auto bob = person("bob").value;
  const auto bot = service("bot").value;
  const auto staff = group("staff").value;
  numbered();
  const auto carol = person("carol").value;

  const auto first = allocate();
  ASSERT_TRUE(first.ok()) << first.message;
  EXPECT_EQ(first.value.users, 2u);
  EXPECT_EQ(first.value.groups, 1u);
  EXPECT_EQ(carol.posix_number, 10000u);
  EXPECT_EQ(read_user(alice.id).posix_number, 10001u);
  EXPECT_EQ(read_user(bob.id).posix_number, 10002u);
  EXPECT_EQ(read_user(carol.id).posix_number, 10000u) << "already numbered, and left";
  EXPECT_FALSE(read_user(bot.id).posix_number);
  EXPECT_EQ(read_group(staff.id).posix_number, 20000u);
  EXPECT_TRUE(rig.audited("ldap.posix.allocate"));

  const auto second = allocate();
  ASSERT_TRUE(second.ok());
  EXPECT_EQ(second.value.users, 0u);
  EXPECT_EQ(second.value.groups, 0u);
}

TEST_F(PosixTest, AChangeKeepsTheNumber) {
  numbered();
  const auto alice = person("alice").value;
  lugh::directory::UserChange change;
  change.display_name = "Alice";
  ASSERT_TRUE(wait_for<Outcome<User>>([&](Executor executor, auto done) {
                rig.directory->update_user(rig.admin, alice.id, change, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_user(alice.id).posix_number, 10000u);
}

// What LDAP shows of them (TODO/2026-11-04-ldap.md, "Entries").
TEST_F(PosixTest, TheEntries) {
  numbered();
  ASSERT_TRUE(group("staff").ok());
  ASSERT_TRUE(person("alice").ok());
  ASSERT_TRUE(service("bot").ok());

  Tree::Settings settings;
  settings.base_dn = "dc=example,dc=com";
  settings.primary_group = "staff";
  settings.home = "/srv/home/{name}";
  settings.shell = "/bin/zsh";
  auto tree = std::make_shared<Tree>(rig.directory, settings);
  Operations::Settings operation_settings;
  auto operations = std::make_shared<Operations>(tree, operation_settings);
  Bound reader;
  reader.dn = "uid=alice,ou=people,dc=example,dc=com";
  reader.caller = lugh::http::Caller{lugh::http::Caller::Kind::user, "id", {lugh::scopes::kDirectoryRead}};

  const auto search = [&](
                          const std::string& base, Filter filter = [] {
                            Filter present;
                            present.kind = Filter::Kind::present;
                            present.attribute = "objectclass";
                            return present;
                          }()) {
    SearchRequest request;
    request.base = base;
    request.scope = Scope::base;
    request.filter = std::move(filter);
    return wait_for<SearchAnswer>([&](Executor executor, auto done) { operations->search(reader, std::move(request), std::nullopt, executor, done); });
  };
  const auto values = [](const SearchEntry& entry, const std::string& type) {
    for (const auto& one : entry.attributes) {
      if (one.type == type) return one.values;
    }
    return std::vector<std::string>{};
  };

  const auto alice = search(reader.dn).entries.at(0);
  const auto classes = values(alice, "objectClass");
  EXPECT_NE(std::find(classes.begin(), classes.end(), "posixAccount"), classes.end());
  EXPECT_EQ(values(alice, "uidNumber"), (std::vector<std::string>{"10000"}));
  EXPECT_EQ(values(alice, "gidNumber"), (std::vector<std::string>{"20000"})) << "the primary group's, not their own";
  EXPECT_EQ(values(alice, "homeDirectory"), (std::vector<std::string>{"/srv/home/alice"}));
  EXPECT_EQ(values(alice, "loginShell"), (std::vector<std::string>{"/bin/zsh"}));

  const auto bot = search("uid=bot,ou=services,dc=example,dc=com").entries.at(0);
  const auto bot_classes = values(bot, "objectClass");
  EXPECT_EQ(std::find(bot_classes.begin(), bot_classes.end(), "posixAccount"), bot_classes.end());
  EXPECT_TRUE(values(bot, "uidNumber").empty());

  const auto staff = search("cn=staff,ou=groups,dc=example,dc=com").entries.at(0);
  const auto group_classes = values(staff, "objectClass");
  EXPECT_NE(std::find(group_classes.begin(), group_classes.end(), "posixGroup"), group_classes.end());
  EXPECT_EQ(values(staff, "gidNumber"), (std::vector<std::string>{"20000"}));

  // Ordering works on them, by number and not as text.
  Filter at_least;
  at_least.kind = Filter::Kind::greater_or_equal;
  at_least.attribute = "uidnumber";
  at_least.value = "9999";
  EXPECT_EQ(search(reader.dn, at_least).entries.size(), 1u);
  at_least.value = "10001";
  EXPECT_TRUE(search(reader.dn, at_least).entries.empty());
}

// With no primary group, a number cannot make a whole posixAccount.
TEST_F(PosixTest, NoPrimaryGroupNoPosixAccount) {
  numbered();
  ASSERT_TRUE(person("alice").ok());
  Tree::Settings settings;
  settings.base_dn = "dc=example,dc=com";
  settings.primary_group = "nobody-made-this";
  auto operations = std::make_shared<Operations>(std::make_shared<Tree>(rig.directory, settings), Operations::Settings{});
  Bound reader;
  reader.caller = lugh::http::Caller{lugh::http::Caller::Kind::user, "id", {lugh::scopes::kDirectoryRead}};
  SearchRequest request;
  request.base = "uid=alice,ou=people,dc=example,dc=com";
  request.filter.kind = Filter::Kind::present;
  request.filter.attribute = "objectclass";
  const auto found =
      wait_for<SearchAnswer>([&](Executor executor, auto done) { operations->search(reader, std::move(request), std::nullopt, executor, done); });
  ASSERT_EQ(found.entries.size(), 1u);
  for (const auto& one : found.entries[0].attributes) EXPECT_NE(one.type, "uidNumber");
}

TEST_F(PosixTest, TheRoute) {
  rig.directory->numbers_set(std::make_shared<PosixNumbers>(rig.store, PosixNumbers::Range{10000, 19999}, PosixNumbers::Range{20000, 29999}));
  lugh::api::LdapRoutes routes(rig.directory);
  routes.register_routes(*rig.router);
  ASSERT_TRUE(person("someone").ok());
  EXPECT_EQ(rig.request(lugh::http::verb::post, "/api/v1/ldap/posix/allocate", "", {}, "Bearer reader").status, 403u) << "a reader may not";
  const auto done = rig.request(lugh::http::verb::post, "/api/v1/ldap/posix/allocate");
  ASSERT_EQ(done.status, 200u);
  EXPECT_EQ(done.body.at("users"), 0) << "numbered when made, and nobody else exists";
  EXPECT_EQ(done.body.at("groups"), 0);
}

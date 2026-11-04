//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/scopes/grants.h"
#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using lugh::Outcome;
using lugh::scopes::Granted;
using lugh::scopes::Grants;
using Scopes = std::vector<std::string>;

namespace {

class GrantsTest : public ::testing::Test {
 protected:
  // T.O.M.S registered as an api, so its scopes may be granted.
  void SetUp() override {
    lugh::apps::App toms;
    toms.name = "T.O.M.S";
    toms.kind = lugh::apps::Kind::api;
    toms.prefix = "toms";
    ASSERT_TRUE(wait_for<Outcome<lugh::apps::Apps::Made>>([&](lugh::Executor executor, auto done) {
                  rig.apps->create(rig.admin, toms, kTestDeadline, executor, done);
                }).ok());
  }

  lugh::directory::Group group(const std::string& name) {
    const auto made = wait_for<Outcome<lugh::directory::Group>>(
        [&](lugh::Executor executor, auto done) { rig.directory->create_group(rig.admin, name, "", kTestDeadline, executor, done); });
    EXPECT_TRUE(made.ok()) << made.message;
    return made.value;
  }

  void join(const std::string& group_id, const std::string& user_id) {
    EXPECT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) {
                  rig.directory->add_member(rig.admin, group_id, user_id, kTestDeadline, executor, done);
                }).ok());
  }

  void leave(const std::string& group_id, const std::string& user_id) {
    EXPECT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) {
                  rig.directory->remove_member(rig.admin, group_id, user_id, kTestDeadline, executor, done);
                }).ok());
  }

  Outcome<Granted> set(const std::string& group_id, Scopes scopes, std::optional<std::uint64_t> expected = std::nullopt) {
    return wait_for<Outcome<Granted>>(
        [&](lugh::Executor executor, auto done) { rig.grants->group_set(rig.admin, group_id, scopes, expected, kTestDeadline, executor, done); });
  }

  Outcome<Granted> of(const std::string& group_id) {
    return wait_for<Outcome<Granted>>([&](lugh::Executor executor, auto done) { rig.grants->group(group_id, kTestDeadline, executor, done); });
  }

  Scopes effective(const std::string& user_id) {
    return read_value<Scopes>([&](lugh::Executor executor, auto done) { rig.grants->effective(user_id, kTestDeadline, executor, done); });
  }

  AuthnRig rig;
};

}  // namespace

TEST_F(GrantsTest, AGroupNeverGrantedHoldsNothingAtVersionZero) {
  const auto staff = group("staff");
  const auto none = of(staff.id);
  ASSERT_TRUE(none.ok()) << none.message;
  EXPECT_TRUE(none.value.scopes.empty());
  EXPECT_EQ(none.value.version, 0u);
  EXPECT_EQ(of("nobody").fault, Fault::not_found);
}

TEST_F(GrantsTest, SetIsSortedOnceAndVersioned) {
  const auto staff = group("staff");
  const auto made = set(staff.id, {"toms:dns", "lugh:directory.read", "toms:dns", "openid"}, 0);
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.scopes, (Scopes{"lugh:directory.read", "openid", "toms:dns"}));
  EXPECT_EQ(made.value.version, 1u);
  EXPECT_EQ(of(staff.id).value.scopes, made.value.scopes);
  EXPECT_TRUE(rig.audited("scopes.set"));

  // The same set again writes nothing.
  EXPECT_EQ(set(staff.id, {"openid", "toms:dns", "lugh:directory.read"}).value.version, 1u);

  // A writer holding an old version loses; the current one wins; clearing writes empty.
  EXPECT_EQ(set(staff.id, {"openid"}, 0).fault, Fault::conflict);
  const auto cleared = set(staff.id, {}, 1);
  ASSERT_TRUE(cleared.ok()) << cleared.message;
  EXPECT_TRUE(cleared.value.scopes.empty());
  EXPECT_EQ(cleared.value.version, 2u);
  EXPECT_EQ(set(staff.id, {"openid"}, 2).value.version, 3u);
}

TEST_F(GrantsTest, OnlyGrantableScopesOnRealGroups) {
  const auto staff = group("staff");
  EXPECT_EQ(set(staff.id, {"lugh:everything"}).fault, Fault::invalid);
  EXPECT_EQ(set(staff.id, {"openid", "two words"}).fault, Fault::invalid);
  EXPECT_EQ(set(staff.id, {"lir:sub:a/#/b"}).fault, Fault::invalid);
  EXPECT_EQ(set("nobody", {"openid"}).fault, Fault::not_found);
  Scopes many;
  for (int i = 0; i <= 256; ++i) many.push_back("app:s" + std::to_string(i));
  EXPECT_EQ(set(staff.id, many).fault, Fault::invalid);
  // Nothing was written by any of those.
  EXPECT_EQ(of(staff.id).value.version, 0u);
}

TEST_F(GrantsTest, EffectiveIsTheUnionOverTheUsersGroups) {
  const auto alice = rig.person("alice");
  const auto bob = rig.person("bob");
  const auto staff = group("staff");
  const auto ops = group("ops");
  ASSERT_TRUE(set(staff.id, {"openid", "toms:dns"}).ok());
  ASSERT_TRUE(set(ops.id, {"toms:dns", "lir:sub:$lir/#", "lugh:audit.read"}).ok());
  join(staff.id, alice.id);
  join(ops.id, alice.id);
  join(staff.id, bob.id);

  EXPECT_EQ(effective(alice.id), (Scopes{"lir:sub:$lir/#", "lugh:audit.read", "openid", "toms:dns"}));
  EXPECT_EQ(effective(bob.id), (Scopes{"openid", "toms:dns"}));

  // Out of a group, out of its scopes, at the next read.
  leave(ops.id, alice.id);
  EXPECT_EQ(effective(alice.id), (Scopes{"openid", "toms:dns"}));
  // In no group, or no such user: nothing.
  EXPECT_TRUE(effective(rig.person("carol").id).empty());
  EXPECT_TRUE(effective("nobody").empty());
}

TEST_F(GrantsTest, ARemovedGroupGrantsNothing) {
  const auto alice = rig.person("alice");
  const auto staff = group("staff");
  ASSERT_TRUE(set(staff.id, {"openid"}).ok());
  join(staff.id, alice.id);
  ASSERT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->remove_group(rig.admin, staff.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_TRUE(effective(alice.id).empty());
}

TEST(GrantsRecord, RoundTripsAndRefusesWhatEncodingWouldNotMake) {
  const Scopes scopes{"lugh:directory.read", "openid"};
  const auto bytes = Grants::encode(scopes);
  EXPECT_EQ(Grants::decode(bytes), scopes);
  EXPECT_EQ(Grants::decode(Grants::encode({})), Scopes{});

  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(Grants::decode(longer));
  EXPECT_FALSE(Grants::decode(std::span(bytes).first(bytes.size() - 1)));
  auto format = bytes;
  format[0] = 2;
  EXPECT_FALSE(Grants::decode(format));
  auto count = bytes;
  count[1] = 0xff;
  EXPECT_FALSE(Grants::decode(count));
}

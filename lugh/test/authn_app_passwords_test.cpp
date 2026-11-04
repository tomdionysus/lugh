//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/app_passwords.h"
#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using lugh::Outcome;
using lugh::authn::AppPasswordMatch;
using lugh::authn::AppPasswords;
using Strings = std::vector<std::string>;

namespace {

class AppPasswordsTest : public ::testing::Test {
 protected:
  Outcome<AppPasswords::Made> create(const std::string& user_id, const std::string& name, Strings scopes = {}, Strings networks = {}) {
    return wait_for<Outcome<AppPasswords::Made>>(
        [&](lugh::Executor executor, auto done) { rig.app_passwords->create(rig.admin, user_id, name, scopes, networks, kTestDeadline, executor, done); });
  }

  Outcome<AppPasswordMatch> verify(const std::string& user_id, const std::string& password, const std::string& source = "192.0.2.9") {
    return wait_for<Outcome<AppPasswordMatch>>(
        [&](lugh::Executor executor, auto done) { rig.app_passwords->verify(user_id, lugh::text_secret(password), source, kTestDeadline, executor, done); });
  }

  std::vector<lugh::authn::AppPasswordInfo> list(const std::string& user_id) {
    return read_value<std::vector<lugh::authn::AppPasswordInfo>>(
        [&](lugh::Executor executor, auto done) { rig.app_passwords->list(user_id, kTestDeadline, executor, done); });
  }

  AuthnRig rig;
};

}  // namespace

TEST_F(AppPasswordsTest, MadeShownOnceAndReadOnlyByDefault) {
  const auto alice = rig.enrolled("alice");
  const auto made = create(alice.id, "mail on the phone");
  ASSERT_TRUE(made.ok()) << made.message;
  const std::string password(lugh::secret_text(made.value.password));
  // Lower case, in eight groups of four.
  EXPECT_EQ(password.size(), 39u);
  EXPECT_EQ(password[4], '-');
  EXPECT_EQ(made.value.info.scopes, Strings{"lugh:directory.read"});
  EXPECT_TRUE(rig.audited("app_password.create"));

  const auto listed = list(alice.id);
  ASSERT_EQ(listed.size(), 1u);
  EXPECT_EQ(listed[0].name, "mail on the phone");
  EXPECT_EQ(listed[0].id, made.value.info.id);

  // Typed any way a person might: case, dashes, spaces.
  auto upper = password;
  std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  std::erase(upper, '-');
  EXPECT_TRUE(verify(alice.id, password).ok());
  EXPECT_TRUE(verify(alice.id, upper).ok());
  const auto match = verify(alice.id, password);
  EXPECT_EQ(match.value.user_id, alice.id);
  EXPECT_EQ(match.value.app_password.id, made.value.info.id);
}

TEST_F(AppPasswordsTest, WhatDoesNotMatchIsRefusedAlike) {
  const auto alice = rig.enrolled("alice");
  const auto bob = rig.enrolled("bob");
  const std::string password(lugh::secret_text(create(alice.id, "nas").value.password));
  auto wrong = password;
  wrong.back() = wrong.back() == 'a' ? 'b' : 'a';
  EXPECT_EQ(verify(alice.id, wrong).fault, Fault::refused);
  EXPECT_EQ(verify(bob.id, password).fault, Fault::refused);
  EXPECT_EQ(verify(alice.id, "not even the shape").fault, Fault::refused);
  EXPECT_EQ(verify("nobody", password).fault, Fault::refused);

  // A disabled user's app passwords stop working.
  ASSERT_TRUE(wait_for<Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->disable_user(rig.admin, alice.id, true, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(verify(alice.id, password).fault, Fault::refused);
}

TEST_F(AppPasswordsTest, ScopesAndNetworks) {
  const auto alice = rig.enrolled("alice");
  const auto made = create(alice.id, "provisioning", {"lugh:directory.write", "lugh:directory.read", "lugh:directory.write"}, {"10.1.0.0/16", "2001:db8::/32"});
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.info.scopes, (Strings{"lugh:directory.read", "lugh:directory.write"}));
  const std::string password(lugh::secret_text(made.value.password));
  EXPECT_TRUE(verify(alice.id, password, "10.1.2.3").ok());
  EXPECT_TRUE(verify(alice.id, password, "::ffff:10.1.2.3").ok());
  EXPECT_TRUE(verify(alice.id, password, "2001:db8::5").ok());
  EXPECT_EQ(verify(alice.id, password, "10.2.0.1").fault, Fault::refused);
  EXPECT_EQ(verify(alice.id, password, "not an address").fault, Fault::refused);

  EXPECT_EQ(create(alice.id, "x", {"lugh:everything"}).fault, Fault::invalid);
  EXPECT_EQ(create(alice.id, "x", {}, {"10.0.0.1/8"}).fault, Fault::invalid);
  EXPECT_EQ(create(alice.id, "").fault, Fault::invalid);
  EXPECT_EQ(create("nobody", "x").fault, Fault::not_found);
}

TEST_F(AppPasswordsTest, RevokedAloneAndForgottenWithTheUser) {
  const auto alice = rig.enrolled("alice");
  const auto one = create(alice.id, "one");
  const auto two = create(alice.id, "two");
  const auto revoke = [&](const std::string& id) {
    return wait_for<Outcome<>>([&](lugh::Executor executor, auto done) { rig.app_passwords->revoke(rig.admin, alice.id, id, kTestDeadline, executor, done); });
  };
  ASSERT_TRUE(revoke(one.value.info.id).ok());
  EXPECT_TRUE(rig.audited("app_password.revoke"));
  EXPECT_EQ(revoke(one.value.info.id).fault, Fault::not_found);
  EXPECT_EQ(revoke("nothing").fault, Fault::not_found);
  EXPECT_EQ(verify(alice.id, std::string(lugh::secret_text(one.value.password))).fault, Fault::refused);
  EXPECT_TRUE(verify(alice.id, std::string(lugh::secret_text(two.value.password))).ok());

  ASSERT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->remove_user(rig.admin, alice.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_TRUE(list(alice.id).empty());
}

TEST_F(AppPasswordsTest, AtMostThirtyTwo) {
  const auto service = wait_for<Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
    rig.directory->create_user(rig.admin, {lugh::directory::Kind::service, "backup", "", "", "", ""}, kTestDeadline, executor, done);
  });
  for (int i = 0; i < 32; ++i) ASSERT_TRUE(create(service.value.id, "n" + std::to_string(i)).ok()) << i;
  EXPECT_EQ(create(service.value.id, "one more").fault, Fault::refused);
}

TEST(AppPasswordRecord, RoundTripsAndRefusesWhatEncodingWouldNotMake) {
  AppPasswords::Record record;
  record.name = "nas";
  record.selector = "ABCD";
  const auto hash = lugh::authn::hash_password(std::vector<unsigned char>{'x'}, {64, 1, 1});
  ASSERT_TRUE(hash.ok);
  record.hash = hash.value;
  record.scopes = {"lugh:directory.read"};
  record.networks = {"10.0.0.0/8"};
  record.created = 5;
  const auto bytes = AppPasswords::encode(record);
  const auto back = AppPasswords::decode(bytes);
  ASSERT_TRUE(back);
  EXPECT_EQ(AppPasswords::encode(*back), bytes);
  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(AppPasswords::decode(longer));
}

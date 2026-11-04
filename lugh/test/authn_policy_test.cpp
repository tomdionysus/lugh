//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/policy.h"
#include "lugh/test/fixtures/authn_rig.h"

using namespace lugh::authn;

TEST(Policy, AcrValues) {
  EXPECT_EQ(acr(Assurance::pwd), "urn:lugh:acr:pwd");
  EXPECT_EQ(acr(Assurance::mfa), "urn:lugh:acr:mfa");
  EXPECT_EQ(acr(Assurance::phr), "urn:lugh:acr:phr");
  EXPECT_EQ(assurance_from_acr("urn:lugh:acr:phr"), Assurance::phr);
  EXPECT_FALSE(assurance_from_acr("urn:lugh:acr:none"));
}

TEST(Policy, MfaForEveryoneUntilSaidOtherwise) {
  AuthnRig rig;
  const auto alice = rig.person("alice");
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->global(kTestDeadline, executor, done); }),
            Assurance::mfa);
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->required(alice.id, kTestDeadline, executor, done); }),
            Assurance::mfa);
}

TEST(Policy, TheStrictestWins) {
  AuthnRig rig;
  const auto alice = rig.person("alice");
  const auto bob = rig.person("bob");
  const auto admins = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                        rig.directory->create_group(rig.admin, "admins", "", kTestDeadline, executor, done);
                      }).value;
  const auto relaxed = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                         rig.directory->create_group(rig.admin, "relaxed", "", kTestDeadline, executor, done);
                       }).value;
  wait_for<lugh::Outcome<lugh::Nothing>>(
      [&](lugh::Executor executor, auto done) { rig.directory->add_member(rig.admin, admins.id, alice.id, kTestDeadline, executor, done); });
  wait_for<lugh::Outcome<lugh::Nothing>>(
      [&](lugh::Executor executor, auto done) { rig.directory->add_member(rig.admin, relaxed.id, alice.id, kTestDeadline, executor, done); });
  wait_for<lugh::Outcome<lugh::Nothing>>(
      [&](lugh::Executor executor, auto done) { rig.directory->add_member(rig.admin, relaxed.id, bob.id, kTestDeadline, executor, done); });

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                rig.policies->group_set(rig.admin, admins.id, Assurance::phr, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                rig.policies->group_set(rig.admin, relaxed.id, Assurance::pwd, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->required(alice.id, kTestDeadline, executor, done); }),
            Assurance::phr);
  // A group cannot lower what the global level asks.
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->required(bob.id, kTestDeadline, executor, done); }),
            Assurance::mfa);

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                rig.policies->global_set(rig.admin, Assurance::pwd, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->required(bob.id, kTestDeadline, executor, done); }),
            Assurance::pwd);

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                rig.policies->group_set(rig.admin, admins.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(read_value<std::optional<lugh::authn::Assurance>>(
      [&](lugh::Executor executor, auto done) { rig.policies->group(admins.id, kTestDeadline, executor, done); }));
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->required(alice.id, kTestDeadline, executor, done); }),
            Assurance::pwd);
  // And set again after clearing.
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                rig.policies->group_set(rig.admin, admins.id, Assurance::mfa, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_value<lugh::authn::Assurance>([&](lugh::Executor executor, auto done) { rig.policies->required(alice.id, kTestDeadline, executor, done); }),
            Assurance::mfa);

  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              rig.policies->group_set(rig.admin, "nothing", Assurance::mfa, kTestDeadline, executor, done);
            }).fault,
            lugh::Fault::not_found);
  EXPECT_TRUE(rig.audited("policy.set"));
}

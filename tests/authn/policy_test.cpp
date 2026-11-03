//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "authn/policy.h"

#include <gtest/gtest.h>

#include "helpers/authn_rig.h"

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
  EXPECT_EQ(run(rig.policies->global()), Assurance::mfa);
  EXPECT_EQ(run(rig.policies->required(alice.id)), Assurance::mfa);
}

TEST(Policy, TheStrictestWins) {
  AuthnRig rig;
  const auto alice = rig.person("alice");
  const auto bob = rig.person("bob");
  const auto admins = run(rig.directory->create_group(rig.admin, "admins", "")).value;
  const auto relaxed = run(rig.directory->create_group(rig.admin, "relaxed", "")).value;
  run(rig.directory->add_member(rig.admin, admins.id, alice.id));
  run(rig.directory->add_member(rig.admin, relaxed.id, alice.id));
  run(rig.directory->add_member(rig.admin, relaxed.id, bob.id));

  ASSERT_TRUE(run(rig.policies->group_set(rig.admin, admins.id, Assurance::phr)).ok());
  ASSERT_TRUE(run(rig.policies->group_set(rig.admin, relaxed.id, Assurance::pwd)).ok());
  EXPECT_EQ(run(rig.policies->required(alice.id)), Assurance::phr);
  // A group cannot lower what the global level asks.
  EXPECT_EQ(run(rig.policies->required(bob.id)), Assurance::mfa);

  ASSERT_TRUE(run(rig.policies->global_set(rig.admin, Assurance::pwd)).ok());
  EXPECT_EQ(run(rig.policies->required(bob.id)), Assurance::pwd);

  ASSERT_TRUE(run(rig.policies->group_set(rig.admin, admins.id, std::nullopt)).ok());
  EXPECT_FALSE(run(rig.policies->group(admins.id)));
  EXPECT_EQ(run(rig.policies->required(alice.id)), Assurance::pwd);
  // And set again after clearing.
  ASSERT_TRUE(run(rig.policies->group_set(rig.admin, admins.id, Assurance::mfa)).ok());
  EXPECT_EQ(run(rig.policies->required(alice.id)), Assurance::mfa);

  EXPECT_EQ(run(rig.policies->group_set(rig.admin, "nothing", Assurance::mfa)).fault, lugh::Fault::not_found);
  EXPECT_TRUE(rig.audited("policy.set"));
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/genesis.h"
#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using lugh::Secret;
using lugh::text_secret;
using namespace lugh::authn;
using Kind = Step::Kind;
using Stage = SignIn::Stage;

namespace {

constexpr const char* kSource = "192.0.2.1";

class GenesisTest : public ::testing::Test {
 protected:
  lugh::Outcome<Secret> genesis() { return run(Genesis(rig.directory, rig.passwords, rig.links, rig.audit).run()); }

  AuthnRig rig;
};

}  // namespace

TEST_F(GenesisTest, RootInAdministratorsWithARandomPassword) {
  const auto password = genesis();
  ASSERT_TRUE(password.ok()) << password.message;
  EXPECT_EQ(password.value.size(), 24u);

  const auto root = read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->user_by_name("root", kTestDeadline, executor, done); });
  ASSERT_TRUE(root);
  EXPECT_EQ(root->kind, lugh::directory::Kind::person);
  EXPECT_FALSE(root->enrolled);
  EXPECT_TRUE(root->email.empty());
  const auto administrators = read_value<std::optional<lugh::directory::Group>>(
      [&](lugh::Executor executor, auto done) { rig.directory->group_by_name("administrators", kTestDeadline, executor, done); });
  ASSERT_TRUE(administrators);
  EXPECT_EQ(read_value<std::vector<std::string>>(
                [&](lugh::Executor executor, auto done) { rig.directory->members(administrators->id, kTestDeadline, executor, done); }),
            std::vector<std::string>{root->id});

  EXPECT_TRUE(run(rig.passwords->verify(root->id, copy_of(password.value))));
  EXPECT_TRUE(rig.audited("genesis"));
}

TEST_F(GenesisTest, OnceOnly) {
  ASSERT_TRUE(genesis().ok());
  EXPECT_EQ(genesis().fault, Fault::refused);
  EXPECT_EQ(
      read_value<std::vector<lugh::directory::User>>([&](lugh::Executor executor, auto done) { rig.directory->users(kTestDeadline, executor, done); }).size(),
      1u);
}

TEST_F(GenesisTest, NotOnADirectoryWithAnyoneInIt) {
  rig.person("alice");
  EXPECT_EQ(genesis().fault, Fault::refused);
  EXPECT_FALSE(read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->user_by_name("root", kTestDeadline, executor, done); }));
}

TEST_F(GenesisTest, EachGenesisAPasswordOfItsOwn) {
  const auto first = genesis().value;
  // Another cluster.
  AuthnRig other;
  const auto second = run(Genesis(other.directory, other.passwords, other.links, other.audit).run()).value;
  EXPECT_FALSE(first == second);
}

TEST_F(GenesisTest, RootsFirstSignInIsEnrolment) {
  const auto password = genesis().value;
  auto& auth = *rig.authenticator;
  const auto first = run(auth.password("root", copy_of(password), kSource));
  ASSERT_EQ(first.kind, Kind::next);
  EXPECT_EQ(first.sign_in.stage, Stage::enrolment);

  const auto setup = run(auth.enrol_begin(first.sign_in, kSource));
  ASSERT_TRUE(setup.ok());
  const auto done = run(auth.enrol_confirm(first.sign_in, setup.value.factor_id, rig.code_for(setup.value.secret), kSource));
  ASSERT_EQ(done.kind, Kind::next);
  EXPECT_EQ(done.sign_in.stage, Stage::complete);
  EXPECT_EQ(done.sign_in.reached, Assurance::mfa);
  EXPECT_EQ(done.recovery_codes.size(), Factors::kRecoveryCodes);
  EXPECT_TRUE(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->user_by_name("root", kTestDeadline, executor, done);
              })->enrolled);

  // From then on, as anyone: the password, then a code.
  rig.advance(std::chrono::seconds(30));
  const auto again = run(auth.password("root", copy_of(password), kSource));
  ASSERT_EQ(again.kind, Kind::next);
  EXPECT_EQ(again.sign_in.stage, Stage::second_factor);
}

TEST_F(GenesisTest, TheFirstSignInHappensOnce) {
  const auto password = genesis().value;
  auto& auth = *rig.authenticator;
  const auto first = run(auth.password("root", copy_of(password), kSource));
  const auto setup = run(auth.enrol_begin(first.sign_in, kSource)).value;
  run(auth.enrol_confirm(first.sign_in, setup.factor_id, rig.code_for(setup.secret), kSource));

  // Reset, root's password alone no longer opens enrolment: a new link must.
  const auto root = *read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->user_by_name("root", kTestDeadline, executor, done); });
  ASSERT_TRUE(run(auth.reset_factors(rig.admin, root.id)).ok());
  EXPECT_EQ(run(auth.password("root", copy_of(password), kSource)).kind, Kind::refused);
}

TEST_F(GenesisTest, AWrongPasswordIsStillWrong) {
  genesis();
  const auto step = run(rig.authenticator->password("root", text_secret("not the generated one"), kSource));
  EXPECT_EQ(step.kind, Kind::refused);
  EXPECT_EQ(step.sign_in.stage, Stage::ended);
}

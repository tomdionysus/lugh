//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/authenticator.h"
#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using lugh::Secret;
using namespace lugh::authn;
using Kind = Step::Kind;
using Stage = SignIn::Stage;

namespace {

constexpr const char* kPassword = "correct horse battery";
constexpr const char* kSource = "192.0.2.1";

// Each step run to its end, keeping the sign-in it hands back, as P6's session will.
class AuthenticatorTest : public ::testing::Test {
 protected:
  Step keep(Step step) {
    sign_in = step.sign_in;
    return step;
  }
  Step password(const std::string& login, const std::string& password, const std::string& source = kSource) {
    return keep(run(auth.password(login, Secret(password), source)));
  }
  Step totp(std::string_view code) { return keep(run(auth.totp(sign_in, std::string(code), kSource))); }
  Step recovery(const Secret& code) { return keep(run(auth.recovery(sign_in, code, kSource))); }
  Step redeem(const Secret& token, const std::string& password) { return keep(run(auth.redeem(token, Secret(password), kSource))); }
  lugh::Outcome<TotpSetup> enrol_begin() { return run(auth.enrol_begin(sign_in, kSource)); }
  Step enrol_confirm(const std::string& factor_id, const std::string& code) { return keep(run(auth.enrol_confirm(sign_in, factor_id, code, kSource))); }

  AuthnRig rig;
  Authenticator& auth = *rig.authenticator;
  SignIn sign_in;
};

}  // namespace

TEST_F(AuthenticatorTest, EnrolmentFromALink) {
  const auto alice = rig.person("alice");
  const auto token = run(rig.links->issue(rig.admin, alice.id)).value;

  ASSERT_EQ(redeem(token, kPassword).kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::enrolment);
  EXPECT_EQ(sign_in.user_id, alice.id);
  // Enrolment is all that is open: a code step is not.
  EXPECT_EQ(totp("123456").kind, Kind::ended);

  const auto setup = enrol_begin();
  ASSERT_TRUE(setup.ok());
  EXPECT_NE(setup.value.uri.reveal().find("Lugh:alice"), std::string::npos);

  const auto done = enrol_confirm(setup.value.factor_id, rig.code_for(setup.value.secret));
  ASSERT_EQ(done.kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::mfa);
  EXPECT_EQ(sign_in.amr, (std::vector<std::string>{"pwd", "otp"}));
  EXPECT_EQ(done.recovery_codes.size(), Factors::kRecoveryCodes);
  EXPECT_TRUE(run(rig.directory->user(alice.id))->enrolled);
  EXPECT_TRUE(rig.audited("signin.complete"));
}

TEST_F(AuthenticatorTest, ARefusedPasswordKeepsTheLink) {
  const auto alice = rig.person("alice");
  const auto token = run(rig.links->issue(rig.admin, alice.id)).value;
  EXPECT_EQ(redeem(token, "short").kind, Kind::refused);
  EXPECT_TRUE(run(rig.links->peek(token)).ok());
  EXPECT_EQ(redeem(token, kPassword).kind, Kind::next);
  EXPECT_EQ(redeem(token, kPassword).kind, Kind::refused);
}

TEST_F(AuthenticatorTest, AWrongEnrolmentCodeCountsAgainstTheSignIn) {
  const auto alice = rig.person("alice");
  redeem(run(rig.links->issue(rig.admin, alice.id)).value, kPassword);
  const auto setup = enrol_begin().value;
  for (int i = 0; i < 4; ++i) EXPECT_EQ(enrol_confirm(setup.factor_id, "000000").kind, Kind::refused);
  EXPECT_EQ(enrol_confirm(setup.factor_id, "000000").kind, Kind::ended);
  EXPECT_EQ(enrol_confirm(setup.factor_id, rig.code_for(setup.secret)).kind, Kind::ended);
  EXPECT_FALSE(run(rig.directory->user(alice.id))->enrolled);
}

TEST_F(AuthenticatorTest, PasswordThenTotp) {
  const auto alice = rig.enrolled("alice");
  ASSERT_EQ(password("alice", kPassword).kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::second_factor);
  EXPECT_EQ(sign_in.required, Assurance::mfa);
  EXPECT_EQ(sign_in.reached, Assurance::pwd);

  ASSERT_EQ(totp(rig.code_for(rig.secret)).kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::mfa);
  EXPECT_EQ(sign_in.amr, (std::vector<std::string>{"pwd", "otp"}));
  EXPECT_EQ(sign_in.user_id, alice.id);
}

TEST_F(AuthenticatorTest, ByAddressToo) {
  rig.enrolled("alice");
  EXPECT_EQ(password("ALICE@example.com", kPassword).kind, Kind::next);
}

TEST_F(AuthenticatorTest, ACodeUsedOnceIsRefusedInTheNextSignIn) {
  rig.enrolled("alice");
  password("alice", kPassword);
  const auto code = rig.code_for(rig.secret);
  ASSERT_EQ(totp(code).kind, Kind::next);

  password("alice", kPassword);
  EXPECT_EQ(totp(code).kind, Kind::refused);
  EXPECT_TRUE(rig.audited("signin.totp.refused"));
}

TEST_F(AuthenticatorTest, FiveWrongCodesEndTheSignIn) {
  rig.enrolled("alice");
  password("alice", kPassword);
  for (int i = 0; i < 4; ++i) EXPECT_EQ(totp("000000").kind, Kind::refused) << i;
  EXPECT_EQ(totp("000000").kind, Kind::ended);
  EXPECT_EQ(sign_in.stage, Stage::ended);
  EXPECT_EQ(totp(rig.code_for(rig.secret)).kind, Kind::ended);
  EXPECT_TRUE(rig.audited("signin.ended"));
}

TEST_F(AuthenticatorTest, ARecoveryCode) {
  rig.enrolled("alice");
  password("alice", kPassword);
  const auto step = recovery(rig.recovery[0]);
  ASSERT_EQ(step.kind, Kind::next);
  EXPECT_EQ(step.recovery_left, 9u);
  EXPECT_EQ(sign_in.reached, Assurance::mfa);
  EXPECT_TRUE(rig.audited("signin.recovery.used"));

  password("alice", kPassword);
  EXPECT_EQ(recovery(rig.recovery[0]).kind, Kind::refused);
}

TEST_F(AuthenticatorTest, RefusalsAllLookTheSame) {
  rig.enrolled("alice");
  const auto bob = rig.enrolled("bob");
  run(rig.directory->disable_user(rig.admin, bob.id, true));
  rig.person("carol");
  run(rig.directory->create_user(rig.admin, {lugh::directory::Kind::service, "backup", "", ""}));

  for (const auto& [login, pass] : std::vector<std::pair<std::string, std::string>>{
           {"alice", "wrong password here"}, {"nobody", kPassword}, {"bob", kPassword}, {"carol", kPassword}, {"backup", kPassword}}) {
    const auto step = password(login, pass, "198.51.100." + std::to_string(login.size()));
    EXPECT_EQ(step.kind, Kind::refused) << login;
    EXPECT_EQ(sign_in.stage, Stage::ended) << login;
    EXPECT_TRUE(sign_in.user_id.empty()) << login;
  }
}

TEST_F(AuthenticatorTest, AnUnknownNameIsNotWrittenToTheAuditLog) {
  password("hunter2-typed-in-the-wrong-box", kPassword);
  for (const auto& entry : run(rig.audit->entries(1, 1000))) {
    EXPECT_EQ(entry.event.subject.find("hunter2"), std::string::npos);
    EXPECT_EQ(entry.event.detail.find("hunter2"), std::string::npos);
  }
}

TEST_F(AuthenticatorTest, ARefusalIsAuditedAsAnonymous) {
  const auto alice = rig.enrolled("alice");
  password("alice", "wrong password here");
  const auto entries = run(rig.audit->entries(1, 1000));
  const auto& last = entries.back();
  EXPECT_EQ(last.event.action, "signin.password.refused");
  EXPECT_EQ(last.event.actor, "anonymous");
  EXPECT_EQ(last.event.subject, alice.id);
  EXPECT_EQ(last.event.detail, "wrong password");
  EXPECT_EQ(last.event.source, kSource);
}

TEST_F(AuthenticatorTest, AStolenPasswordCannotEnrol) {
  // A person who set a password through a link and stopped there.
  const auto alice = rig.person("alice");
  run(auth.redeem(run(rig.links->issue(rig.admin, alice.id)).value, Secret(kPassword), kSource));
  EXPECT_EQ(password("alice", kPassword).kind, Kind::refused);
  EXPECT_EQ(enrol_begin().fault, Fault::refused);
}

TEST_F(AuthenticatorTest, FailuresBackOffPerAccount) {
  rig.enrolled("alice");
  for (int i = 0; i < 5; ++i) password("alice", "wrong password here", "198.51.100." + std::to_string(i));
  const auto step = password("alice", kPassword, "203.0.113.9");
  EXPECT_EQ(step.kind, Kind::wait);
  EXPECT_EQ(step.retry_after, std::chrono::seconds(1));

  rig.clock->advance(std::chrono::seconds(1));
  EXPECT_EQ(password("alice", kPassword, "203.0.113.9").kind, Kind::next);
  // And a success starts the account again.
  EXPECT_EQ(password("alice", "wrong password here").kind, Kind::refused);
  EXPECT_EQ(password("alice", kPassword).kind, Kind::next);
}

TEST_F(AuthenticatorTest, FailuresBackOffPerAddress) {
  rig.enrolled("alice");
  for (int i = 0; i < 20; ++i) password("guess" + std::to_string(i), "wrong password here");
  EXPECT_EQ(password("alice", kPassword).kind, Kind::wait);
  EXPECT_EQ(password("alice", kPassword, "203.0.113.9").kind, Kind::next);
}

TEST_F(AuthenticatorTest, ASignInHasALifetime) {
  rig.enrolled("alice");
  password("alice", kPassword);
  rig.clock->advance(std::chrono::minutes(16));
  EXPECT_EQ(totp(rig.code_for(rig.secret)).kind, Kind::ended);
}

TEST_F(AuthenticatorTest, APasswordAloneWhenPolicySaysSo) {
  run(rig.policies->global_set(rig.admin, Assurance::pwd));
  const auto alice = rig.person("alice");
  run(rig.passwords->set(rig.admin, alice, Secret(kPassword)));
  run(rig.directory->enrolled_set(rig.admin, alice.id, true));

  ASSERT_EQ(password("alice", kPassword).kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::pwd);
  EXPECT_EQ(sign_in.amr, std::vector<std::string>{"pwd"});
}

TEST_F(AuthenticatorTest, TheLastFactorStaysWhilePolicyNeedsIt) {
  const auto alice = rig.enrolled("alice");
  const auto factors = run(rig.factors->list(alice.id));
  std::string totp;
  std::string recovery;
  for (const auto& factor : factors) (factor.kind == FactorKind::totp ? totp : recovery) = factor.id;

  EXPECT_EQ(run(auth.remove_factor(rig.admin, alice.id, totp)).fault, Fault::refused);
  EXPECT_TRUE(run(auth.remove_factor(rig.admin, alice.id, recovery)).ok());
  EXPECT_EQ(run(auth.remove_factor(rig.admin, alice.id, "nothing")).fault, Fault::not_found);

  run(rig.policies->global_set(rig.admin, Assurance::pwd));
  EXPECT_TRUE(run(auth.remove_factor(rig.admin, alice.id, totp)).ok());
}

TEST_F(AuthenticatorTest, AResetMeansEnrollingAgain) {
  const auto alice = rig.enrolled("alice");
  ASSERT_TRUE(run(auth.reset_factors(rig.admin, alice.id)).ok());
  EXPECT_FALSE(run(rig.directory->user(alice.id))->enrolled);
  EXPECT_TRUE(run(rig.factors->list(alice.id)).empty());
  EXPECT_EQ(password("alice", kPassword).kind, Kind::refused);

  // Back through a new link, with a new password.
  const auto token = run(rig.links->issue(rig.admin, alice.id)).value;
  ASSERT_EQ(redeem(token, "a different passphrase").kind, Kind::next);
  const auto setup = enrol_begin().value;
  ASSERT_EQ(enrol_confirm(setup.factor_id, rig.code_for(setup.secret)).kind, Kind::next);
  EXPECT_TRUE(run(rig.directory->user(alice.id))->enrolled);
}

TEST_F(AuthenticatorTest, EveryStepIsAudited) {
  rig.enrolled("alice");
  password("alice", kPassword);
  totp(rig.code_for(rig.secret));

  const auto actions = rig.actions();
  for (const auto* action : {"user.create", "enrolment.issue", "enrolment.redeem", "password.set", "factor.totp.begin", "factor.totp.confirm",
                             "factor.recovery.generate", "user.enrolled", "signin.password.accepted", "signin.complete"}) {
    EXPECT_NE(std::find(actions.begin(), actions.end(), action), actions.end()) << action;
  }
  EXPECT_TRUE(run(rig.audit->verify()).ok);
}

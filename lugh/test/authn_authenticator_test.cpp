//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/authenticator.h"
#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/test/fixtures/soft_authenticator.h"

using lugh::Fault;
using lugh::Secret;
using lugh::text_secret;
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
    return keep(wait_for<lugh::authn::Step>(
        [&](lugh::Executor executor, auto done) { auth->password(login, text_secret(password), source, kTestDeadline, executor, done); }));
  }
  Step totp(std::string_view code) {
    return keep(wait_for<lugh::authn::Step>(
        [&](lugh::Executor executor, auto done) { auth->totp(sign_in, std::string(code), kSource, kTestDeadline, executor, done); }));
  }
  Step recovery(const Secret& code) {
    return keep(wait_for<lugh::authn::Step>(
        [&](lugh::Executor executor, auto done) { auth->recovery(sign_in, copy_of(code), kSource, kTestDeadline, executor, done); }));
  }
  Step redeem(const Secret& token, const std::string& password) {
    return keep(wait_for<lugh::authn::Step>(
        [&](lugh::Executor executor, auto done) { auth->redeem(copy_of(token), text_secret(password), kSource, kTestDeadline, executor, done); }));
  }
  lugh::Outcome<TotpSetup> enrol_begin() {
    return wait_for<lugh::Outcome<lugh::authn::TotpSetup>>(
        [&](lugh::Executor executor, auto done) { auth->enrol_begin(sign_in, kSource, kTestDeadline, executor, done); });
  }
  Step enrol_confirm(const std::string& factor_id, const std::string& code) {
    return keep(wait_for<lugh::authn::Step>(
        [&](lugh::Executor executor, auto done) { auth->enrol_confirm(sign_in, factor_id, code, kSource, kTestDeadline, executor, done); }));
  }

  AuthnRig rig;
  std::shared_ptr<Authenticator>& auth = rig.authenticator;
  SignIn sign_in;
};

}  // namespace

TEST_F(AuthenticatorTest, EnrolmentFromALink) {
  const auto alice = rig.person("alice");
  const auto token = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                       rig.links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;

  ASSERT_EQ(redeem(token, kPassword).kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::enrolment);
  EXPECT_EQ(sign_in.user_id, alice.id);
  // Enrolment is all that is open: a code step is not.
  EXPECT_EQ(totp("123456").kind, Kind::ended);

  const auto setup = enrol_begin();
  ASSERT_TRUE(setup.ok());
  EXPECT_NE(lugh::secret_text(setup.value.uri).find("Lugh:alice"), std::string::npos);

  const auto finished = enrol_confirm(setup.value.factor_id, rig.code_for(setup.value.secret));
  ASSERT_EQ(finished.kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::mfa);
  EXPECT_EQ(sign_in.amr, (std::vector<std::string>{"pwd", "otp"}));
  EXPECT_EQ(finished.recovery_codes.size(), Factors::kRecoveryCodes);
  EXPECT_TRUE(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->user(alice.id, kTestDeadline, executor, done);
              })->enrolled);
  EXPECT_TRUE(rig.audited("signin.complete"));
}

TEST_F(AuthenticatorTest, ARefusedPasswordKeepsTheLink) {
  const auto alice = rig.person("alice");
  const auto token = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                       rig.links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  EXPECT_EQ(redeem(token, "short").kind, Kind::refused);
  EXPECT_TRUE(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { rig.links->peek(copy_of(token), kTestDeadline, executor, done); }).ok());
  EXPECT_EQ(redeem(token, kPassword).kind, Kind::next);
  EXPECT_EQ(redeem(token, kPassword).kind, Kind::refused);
}

TEST_F(AuthenticatorTest, AWrongEnrolmentCodeCountsAgainstTheSignIn) {
  const auto alice = rig.person("alice");
  redeem(wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
           rig.links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
         }).value,
         kPassword);
  const auto setup = enrol_begin().value;
  for (int i = 0; i < 4; ++i) EXPECT_EQ(enrol_confirm(setup.factor_id, "000000").kind, Kind::refused);
  EXPECT_EQ(enrol_confirm(setup.factor_id, "000000").kind, Kind::ended);
  EXPECT_EQ(enrol_confirm(setup.factor_id, rig.code_for(setup.secret)).kind, Kind::ended);
  EXPECT_FALSE(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                 rig.directory->user(alice.id, kTestDeadline, executor, done);
               })->enrolled);
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
  wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->disable_user(rig.admin, bob.id, true, std::nullopt, kTestDeadline, executor, done); });
  rig.person("carol");
  wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
    rig.directory->create_user(rig.admin, {lugh::directory::Kind::service, "backup", "", "", "", ""}, kTestDeadline, executor, done);
  });

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
  for (const auto& entry : audit_entries(rig.audit, 1, 1000)) {
    EXPECT_EQ(entry.event.subject.find("hunter2"), std::string::npos);
    EXPECT_EQ(entry.event.detail.find("hunter2"), std::string::npos);
  }
}

TEST_F(AuthenticatorTest, ARefusalIsAuditedAsAnonymous) {
  const auto alice = rig.enrolled("alice");
  password("alice", "wrong password here");
  const auto entries = audit_entries(rig.audit, 1, 1000);
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
  wait_for<lugh::authn::Step>([&](lugh::Executor executor, auto done) {
    auth->redeem(wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor inner, auto issued) {
                   rig.links->issue(rig.admin, alice.id, kTestDeadline, inner, issued);
                 }).value,
                 text_secret(kPassword), kSource, kTestDeadline, executor, done);
  });
  EXPECT_EQ(password("alice", kPassword).kind, Kind::refused);
  EXPECT_EQ(enrol_begin().fault, Fault::refused);
}

TEST_F(AuthenticatorTest, FailuresBackOffPerAccount) {
  rig.enrolled("alice");
  for (int i = 0; i < 5; ++i) password("alice", "wrong password here", "198.51.100." + std::to_string(i));
  const auto step = password("alice", kPassword, "203.0.113.9");
  EXPECT_EQ(step.kind, Kind::wait);
  EXPECT_EQ(step.retry_after, std::chrono::seconds(1));

  rig.advance(std::chrono::seconds(1));
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
  rig.advance(std::chrono::minutes(16));
  EXPECT_EQ(totp(rig.code_for(rig.secret)).kind, Kind::ended);
}

TEST_F(AuthenticatorTest, APasswordAloneWhenPolicySaysSo) {
  wait_for<lugh::Outcome<lugh::Nothing>>(
      [&](lugh::Executor executor, auto done) { rig.policies->global_set(rig.admin, Assurance::pwd, kTestDeadline, executor, done); });
  const auto alice = rig.person("alice");
  wait_for<lugh::Outcome<lugh::Nothing>>(
      [&](lugh::Executor executor, auto done) { rig.passwords->set(rig.admin, alice, text_secret(kPassword), kTestDeadline, executor, done); });
  wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->enrolled_set(rig.admin, alice.id, true, kTestDeadline, executor, done); });

  ASSERT_EQ(password("alice", kPassword).kind, Kind::next);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::pwd);
  EXPECT_EQ(sign_in.amr, std::vector<std::string>{"pwd"});
}

TEST_F(AuthenticatorTest, TheLastFactorStaysWhilePolicyNeedsIt) {
  const auto alice = rig.enrolled("alice");
  const auto factors =
      read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) { rig.factors->list(alice.id, kTestDeadline, executor, done); });
  std::string totp;
  std::string recovery;
  for (const auto& factor : factors) (factor.kind == FactorKind::totp ? totp : recovery) = factor.id;

  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              auth->remove_factor(rig.admin, alice.id, totp, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                auth->remove_factor(rig.admin, alice.id, recovery, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              auth->remove_factor(rig.admin, alice.id, "nothing", kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);

  wait_for<lugh::Outcome<lugh::Nothing>>(
      [&](lugh::Executor executor, auto done) { rig.policies->global_set(rig.admin, Assurance::pwd, kTestDeadline, executor, done); });
  EXPECT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                auth->remove_factor(rig.admin, alice.id, totp, kTestDeadline, executor, done);
              }).ok());
}

TEST_F(AuthenticatorTest, AResetMeansEnrollingAgain) {
  const auto alice = rig.enrolled("alice");
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                auth->reset_factors(rig.admin, alice.id, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                 rig.directory->user(alice.id, kTestDeadline, executor, done);
               })->enrolled);
  EXPECT_TRUE(read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
                rig.factors->list(alice.id, kTestDeadline, executor, done);
              }).empty());
  EXPECT_EQ(password("alice", kPassword).kind, Kind::refused);

  // Back through a new link, with a new password.
  const auto token = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                       rig.links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  ASSERT_EQ(redeem(token, "a different passphrase").kind, Kind::next);
  const auto setup = enrol_begin().value;
  ASSERT_EQ(enrol_confirm(setup.factor_id, rig.code_for(setup.secret)).kind, Kind::next);
  EXPECT_TRUE(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->user(alice.id, kTestDeadline, executor, done);
              })->enrolled);
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
  EXPECT_TRUE(audit_verify(rig.audit).ok);
}

// WebAuthn (TODO/2026-11-15-p11-webauthn.md, W4): enrolment by a credential, a credential as the
// second factor, and a passkey alone, each reaching phr.
namespace {

class WebAuthnSignInTest : public AuthenticatorTest {
 protected:
  static constexpr const char* kChallenge = "a challenge of 32 bytes, random!";

  static lugh::webauthn::Expected expected(bool user_verification = false) {
    lugh::webauthn::Expected out;
    out.rp_id = "localhost";
    out.origins = {"https://localhost"};
    out.challenge = kChallenge;
    out.user_verification = user_verification;
    return out;
  }

  static lugh::Bytes bytes_of(const std::vector<std::uint8_t>& in) { return lugh::Bytes(in.begin(), in.end()); }

  std::string id_of(const soft_authenticator::Authenticator& authenticator) const {
    return std::string(authenticator.credential_id().begin(), authenticator.credential_id().end());
  }

  // Alice, from her enrolment link to signed in by the credential: the setup for the rest.
  lugh::directory::User enrolled_with(const soft_authenticator::Authenticator& authenticator) {
    const auto alice = rig.person("alice");
    const auto token = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                         rig.links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                       }).value;
    EXPECT_EQ(redeem(token, kPassword).kind, Kind::next);
    const auto made = authenticator.create(kChallenge);
    const auto step = keep(wait_for<lugh::authn::Step>([&](lugh::Executor executor, auto done) {
      auth->enrol_webauthn(sign_in, "laptop", expected(true), bytes_of(made.client_data_json), bytes_of(made.attestation_object), kSource, kTestDeadline,
                           executor, done);
    }));
    EXPECT_EQ(step.kind, Kind::next);
    EXPECT_EQ(step.recovery_codes.size(), Factors::kRecoveryCodes);
    return alice;
  }

  Step second_factor(soft_authenticator::Authenticator& authenticator) {
    const auto proof = authenticator.get(kChallenge);
    return keep(wait_for<lugh::authn::Step>([&](lugh::Executor executor, auto done) {
      auth->webauthn(sign_in, id_of(authenticator), expected(), bytes_of(proof.client_data_json), bytes_of(proof.authenticator_data), bytes_of(proof.signature),
                     kSource, kTestDeadline, executor, done);
    }));
  }

  Step passkey(soft_authenticator::Authenticator& authenticator, const std::string& user_handle, const std::string& source = kSource) {
    const auto proof = authenticator.get(kChallenge);
    return keep(wait_for<lugh::authn::Step>([&](lugh::Executor executor, auto done) {
      auth->passkey(user_handle, id_of(authenticator), expected(), bytes_of(proof.client_data_json), bytes_of(proof.authenticator_data),
                    bytes_of(proof.signature), source, kTestDeadline, executor, done);
    }));
  }
};

}  // namespace

TEST_F(WebAuthnSignInTest, EnrolmentByACredentialReachesPhr) {
  soft_authenticator::Authenticator authenticator;
  const auto alice = enrolled_with(authenticator);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::phr);
  EXPECT_EQ(sign_in.amr, (std::vector<std::string>{"pwd", "hwk", "user"}));
  EXPECT_TRUE(read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->user(alice.id, kTestDeadline, executor, done);
              })->enrolled);
}

TEST_F(WebAuthnSignInTest, APasswordThenACredential) {
  soft_authenticator::Authenticator authenticator;
  enrolled_with(authenticator);
  ASSERT_EQ(password("alice", kPassword).kind, Kind::next);
  ASSERT_EQ(sign_in.stage, Stage::second_factor);
  // A security key without a PIN: still phishing-resistant, with the password.
  authenticator.user_verified = false;
  ASSERT_EQ(second_factor(authenticator).kind, Kind::next);
  EXPECT_EQ(sign_in.reached, Assurance::phr);
  EXPECT_EQ(sign_in.amr, (std::vector<std::string>{"pwd", "hwk"}));
  EXPECT_TRUE(rig.audited("signin.complete"));
}

TEST_F(WebAuthnSignInTest, AWrongAssertionCountsAsAWrongCode) {
  soft_authenticator::Authenticator authenticator;
  enrolled_with(authenticator);
  ASSERT_EQ(password("alice", kPassword).kind, Kind::next);
  soft_authenticator::Authenticator stranger;
  const auto proof = stranger.get(kChallenge);
  const auto refused = keep(wait_for<lugh::authn::Step>([&](lugh::Executor executor, auto done) {
    auth->webauthn(sign_in, id_of(authenticator), expected(), bytes_of(proof.client_data_json), bytes_of(proof.authenticator_data), bytes_of(proof.signature),
                   kSource, kTestDeadline, executor, done);
  }));
  EXPECT_EQ(refused.kind, Kind::refused);
  EXPECT_EQ(sign_in.wrong_codes, 1u);
  EXPECT_TRUE(rig.audited("signin.webauthn.refused"));
  EXPECT_EQ(second_factor(authenticator).kind, Kind::next) << "the right credential still signs in";
}

TEST_F(WebAuthnSignInTest, APasskeyAloneSignsInAtPhr) {
  soft_authenticator::Authenticator authenticator;
  authenticator.backup_eligible = true;
  authenticator.backed_up = true;
  const auto alice = enrolled_with(authenticator);
  sign_in = {};
  const auto step = passkey(authenticator, alice.id);
  ASSERT_EQ(step.kind, Kind::next);
  EXPECT_EQ(sign_in.user_id, alice.id);
  EXPECT_EQ(sign_in.stage, Stage::complete);
  EXPECT_EQ(sign_in.reached, Assurance::phr);
  EXPECT_EQ(sign_in.amr, (std::vector<std::string>{"swk", "user"}));
}

TEST_F(WebAuthnSignInTest, APasskeyMustVerifyTheUser) {
  soft_authenticator::Authenticator authenticator;
  const auto alice = enrolled_with(authenticator);
  authenticator.user_verified = false;
  EXPECT_EQ(passkey(authenticator, alice.id).kind, Kind::refused) << "a key that only saw a touch is not a password";
  EXPECT_TRUE(rig.audited("signin.passkey.refused"));
}

// Whatever is wrong, a passkey sign-in is refused the same way, and backs off.
TEST_F(WebAuthnSignInTest, PasskeyRefusalsLookTheSame) {
  soft_authenticator::Authenticator authenticator;
  const auto alice = enrolled_with(authenticator);
  EXPECT_EQ(passkey(authenticator, "no-such-user").kind, Kind::refused);
  soft_authenticator::Authenticator stranger;
  EXPECT_EQ(passkey(stranger, alice.id).kind, Kind::refused) << "a credential not hers";
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->disable_user(rig.admin, alice.id, true, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(passkey(authenticator, alice.id).kind, Kind::refused) << "disabled";

  // Each refusal counted against the account, from whatever address: past five, it waits.
  for (int i = 0; i < 5; ++i) passkey(stranger, alice.id, "198.51.100." + std::to_string(i));
  EXPECT_EQ(passkey(stranger, alice.id, "198.51.100.99").kind, Kind::wait);
}

// An application asked for phr (W5b): the sign-in requires it, so a code will not finish it and
// a credential will.
TEST_F(WebAuthnSignInTest, WhereAnApplicationWantsPhrOnlyACredentialWillDo) {
  soft_authenticator::Authenticator authenticator;
  enrolled_with(authenticator);
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::authn::TotpSetup>>([&](lugh::Executor executor, auto done) {
                rig.factors->totp_begin(rig.admin, sign_in.user_id, "Lugh", "alice", kTestDeadline, executor, done);
              }).ok());

  const auto step = keep(wait_for<lugh::authn::Step>(
      [&](lugh::Executor executor, auto done) { auth->password("alice", text_secret(kPassword), kSource, kTestDeadline, executor, done, Assurance::phr); }));
  ASSERT_EQ(step.kind, Kind::next);
  EXPECT_EQ(sign_in.required, Assurance::phr);
  EXPECT_EQ(totp("123456").kind, Kind::refused) << "a code is not phishing-resistant";
  EXPECT_EQ(sign_in.wrong_codes, 1u);
  ASSERT_EQ(second_factor(authenticator).kind, Kind::next);
  EXPECT_EQ(sign_in.reached, Assurance::phr);

  // A request can only raise what the policy requires.
  ASSERT_EQ(password("alice", kPassword).kind, Kind::next);
  EXPECT_EQ(sign_in.required, Assurance::mfa);
}

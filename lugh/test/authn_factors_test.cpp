//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <set>

#include "lugh/authn/factors.h"
#include "lugh/authn/totp.h"
#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/test/fixtures/soft_authenticator.h"

using lugh::Fault;
using lugh::Secret;
using namespace lugh::authn;

namespace {

class FactorsTest : public ::testing::Test {
 protected:
  void SetUp() override { alice = rig.person("alice"); }

  // A confirmed TOTP factor: its setup.
  TotpSetup confirmed_totp() {
    auto setup = wait_for<lugh::Outcome<lugh::authn::TotpSetup>>(
        [&](lugh::Executor executor, auto done) { factors->totp_begin(rig.admin, alice.id, "Lugh", "alice", kTestDeadline, executor, done); });
    EXPECT_TRUE(setup.ok()) << setup.message;
    EXPECT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                  factors->totp_confirm(rig.admin, alice.id, setup.value.factor_id, rig.code_for(setup.value.secret), kTestDeadline, executor, done);
                }).ok());
    rig.advance(std::chrono::seconds(30));
    return std::move(setup.value);
  }

  AuthnRig rig;
  std::shared_ptr<Factors>& factors = rig.factors;
  lugh::directory::User alice;
};

}  // namespace

TEST_F(FactorsTest, ATotpSecretCountsOnlyOnceConfirmed) {
  auto setup = wait_for<lugh::Outcome<lugh::authn::TotpSetup>>(
      [&](lugh::Executor executor, auto done) { factors->totp_begin(rig.admin, alice.id, "Lugh", "alice", kTestDeadline, executor, done); });
  ASSERT_TRUE(setup.ok());
  EXPECT_EQ(setup.value.secret.size(), 32u);
  EXPECT_EQ(lugh::secret_text(setup.value.uri).rfind("otpauth://totp/Lugh:alice?secret=", 0), 0u);
  EXPECT_FALSE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));
  ASSERT_EQ(read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
              factors->list(alice.id, kTestDeadline, executor, done);
            }).size(),
            1u);
  EXPECT_FALSE(
      read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) { factors->list(alice.id, kTestDeadline, executor, done); })[0]
          .confirmed);

  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_confirm(rig.admin, alice.id, setup.value.factor_id, "000000", kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_FALSE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                factors->totp_confirm(rig.admin, alice.id, setup.value.factor_id, rig.code_for(setup.value.secret), kTestDeadline, executor, done);
              }).ok());
  EXPECT_TRUE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_confirm(rig.admin, alice.id, setup.value.factor_id, rig.code_for(setup.value.secret), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_TRUE(rig.audited("factor.totp.begin"));
  EXPECT_TRUE(rig.audited("factor.totp.confirm"));
}

TEST_F(FactorsTest, BeginningAgainReplacesAnUnconfirmedSecret) {
  const auto first = wait_for<lugh::Outcome<lugh::authn::TotpSetup>>([&](lugh::Executor executor, auto done) {
                       factors->totp_begin(rig.admin, alice.id, "Lugh", "alice", kTestDeadline, executor, done);
                     }).value;
  const auto second = wait_for<lugh::Outcome<lugh::authn::TotpSetup>>([&](lugh::Executor executor, auto done) {
                        factors->totp_begin(rig.admin, alice.id, "Lugh", "alice", kTestDeadline, executor, done);
                      }).value;
  EXPECT_NE(first.factor_id, second.factor_id);
  ASSERT_EQ(read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
              factors->list(alice.id, kTestDeadline, executor, done);
            }).size(),
            1u);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_confirm(rig.admin, alice.id, first.factor_id, rig.code_for(first.secret), kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
}

TEST_F(FactorsTest, ACodeWorksOnce) {
  const auto setup = confirmed_totp();
  const auto code = rig.code_for(setup.secret);
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                factors->totp_check(alice.id, code, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_check(alice.id, code, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);

  // Nor does the code before it, once a later one has been used.
  rig.advance(std::chrono::seconds(30));
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_check(alice.id, rig.code_for(setup.secret, -1), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                factors->totp_check(alice.id, rig.code_for(setup.secret), kTestDeadline, executor, done);
              }).ok());
}

TEST_F(FactorsTest, TheUsedStepSurvivesARestart) {
  const auto setup = confirmed_totp();
  const auto code = rig.code_for(setup.secret);
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                factors->totp_check(alice.id, code, kTestDeadline, executor, done);
              }).ok());
  auto again = std::make_shared<Factors>(rig.logger, rig.store, rig.wall, rig.audit, test_pool(), kTestArgon2);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              again->totp_check(alice.id, code, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
}

TEST_F(FactorsTest, ACodeIsOnlyForItsOwner) {
  const auto setup = confirmed_totp();
  const auto bob = rig.person("bob");
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_check(bob.id, rig.code_for(setup.secret), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->totp_confirm(rig.admin, bob.id, setup.factor_id, rig.code_for(setup.secret), kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->remove(rig.admin, bob.id, setup.factor_id, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
}

TEST_F(FactorsTest, RecoveryCodes) {
  const auto codes = wait_for<lugh::Outcome<std::vector<lugh::Secret>>>(
      [&](lugh::Executor executor, auto done) { factors->recovery_generate(rig.admin, alice.id, kTestDeadline, executor, done); });
  ASSERT_TRUE(codes.ok());
  ASSERT_EQ(codes.value.size(), Factors::kRecoveryCodes);

  std::set<std::string> distinct;
  for (const auto& code : codes.value) {
    // "abcd-efgh-ijkl-mnop"
    ASSERT_EQ(code.size(), 19u);
    EXPECT_EQ(lugh::secret_text(code)[4], '-');
    distinct.insert(std::string(lugh::secret_text(code)));
  }
  EXPECT_EQ(distinct.size(), Factors::kRecoveryCodes);
  // Codes stand in for a factor; they are not one.
  EXPECT_FALSE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));

  const auto used = wait_for<lugh::Outcome<std::size_t>>(
      [&](lugh::Executor executor, auto done) { factors->recovery_use(alice.id, copy_of(codes.value[3]), kTestDeadline, executor, done); });
  ASSERT_TRUE(used.ok());
  EXPECT_EQ(used.value, 9u);
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, copy_of(codes.value[3]), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);

  // As typed: upper case, no dashes, spaces.
  std::string typed;
  for (const char c : lugh::secret_text(codes.value[4])) {
    if (c != '-') typed.push_back(static_cast<char>(std::toupper(c)));
  }
  typed.insert(8, " ");
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, lugh::text_secret(typed), kTestDeadline, executor, done);
            }).value,
            8u);
  EXPECT_EQ(
      read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) { factors->list(alice.id, kTestDeadline, executor, done); })
          .at(0)
          .remaining,
      8u);
}

TEST_F(FactorsTest, AWrongRecoveryCodeIsRefused) {
  const auto codes = wait_for<lugh::Outcome<std::vector<lugh::Secret>>>([&](lugh::Executor executor, auto done) {
                       factors->recovery_generate(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  // The right slot, the wrong rest.
  std::string wrong(lugh::secret_text(codes[0]));
  wrong.back() = wrong.back() == 'a' ? 'b' : 'a';
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, lugh::text_secret(wrong), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, lugh::text_secret("not a code"), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, lugh::text_secret(""), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_EQ(
      read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) { factors->list(alice.id, kTestDeadline, executor, done); })
          .at(0)
          .remaining,
      10u);
}

TEST_F(FactorsTest, NewRecoveryCodesReplaceTheOld) {
  const auto old = wait_for<lugh::Outcome<std::vector<lugh::Secret>>>([&](lugh::Executor executor, auto done) {
                     factors->recovery_generate(rig.admin, alice.id, kTestDeadline, executor, done);
                   }).value;
  const auto fresh = wait_for<lugh::Outcome<std::vector<lugh::Secret>>>([&](lugh::Executor executor, auto done) {
                       factors->recovery_generate(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, copy_of(old[0]), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_TRUE(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
                factors->recovery_use(alice.id, copy_of(fresh[0]), kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
              factors->list(alice.id, kTestDeadline, executor, done);
            }).size(),
            1u);
}

TEST_F(FactorsTest, TheStoredRecordsHoldNoCode) {
  const auto codes = wait_for<lugh::Outcome<std::vector<lugh::Secret>>>([&](lugh::Executor executor, auto done) {
                       factors->recovery_generate(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  for (const auto& record : rig.store->list_now(Factors::kTable)) {
    const std::string value(record.value.begin(), record.value.end());
    for (const auto& code : codes) {
      std::string normal;
      for (const char c : lugh::secret_text(code)) {
        if (c != '-') normal.push_back(static_cast<char>(std::toupper(c)));
      }
      EXPECT_EQ(value.find(normal), std::string::npos);
    }
  }
}

TEST_F(FactorsTest, RemoveAndForget) {
  const auto setup = confirmed_totp();
  wait_for<lugh::Outcome<std::vector<lugh::Secret>>>(
      [&](lugh::Executor executor, auto done) { factors->recovery_generate(rig.admin, alice.id, kTestDeadline, executor, done); });
  ASSERT_EQ(read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
              factors->list(alice.id, kTestDeadline, executor, done);
            }).size(),
            2u);

  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                factors->remove(rig.admin, alice.id, setup.factor_id, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
              factors->remove(rig.admin, alice.id, setup.factor_id, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);

  confirmed_totp();
  ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { factors->forget(rig.admin, alice.id, kTestDeadline, executor, done); }).ok);
  EXPECT_TRUE(read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
                factors->list(alice.id, kTestDeadline, executor, done);
              }).empty());
  EXPECT_TRUE(rig.audited("factor.reset"));
}

TEST_F(FactorsTest, RecordsRoundTripAndRefuseTheRest) {
  TotpRecord totp;
  totp.confirmed = true;
  totp.last_step = 42;
  totp.created = 7;
  totp.secret = lugh::SecureBuffer(20, 0x11);
  const auto encoded = encode(totp);
  const auto back = decode_totp(encoded);
  ASSERT_TRUE(back);
  EXPECT_TRUE(back->confirmed);
  EXPECT_EQ(back->last_step, 42u);
  EXPECT_EQ(back->secret, totp.secret);
  EXPECT_FALSE(decode_recovery(encoded));
  for (std::size_t length = 0; length < encoded.size(); ++length) EXPECT_FALSE(decode_totp(std::span(encoded).first(length))) << length;

  totp.last_step.reset();
  EXPECT_FALSE(decode_totp(encode(totp))->last_step);
}

// WebAuthn credentials (TODO/2026-11-15-p11-webauthn.md, W3), with the software authenticator.
class WebAuthnFactorsTest : public FactorsTest {
 protected:
  static constexpr const char* kWebAuthnChallenge = "a challenge of 32 bytes, random!";

  static lugh::webauthn::Expected webauthn_expected() {
    lugh::webauthn::Expected out;
    out.rp_id = "localhost";
    out.origins = {"https://localhost"};
    out.challenge = kWebAuthnChallenge;
    out.user_verification = true;
    return out;
  }

  static lugh::Bytes bytes_of(const std::vector<std::uint8_t>& in) { return lugh::Bytes(in.begin(), in.end()); }

  lugh::Outcome<FactorInfo> register_with(const soft_authenticator::Authenticator& authenticator, const std::string& user_id, std::string name = "laptop") {
    const auto made = authenticator.create(kWebAuthnChallenge);
    return wait_for<lugh::Outcome<FactorInfo>>([&](lugh::Executor executor, auto done) {
      factors->webauthn_register(rig.admin, user_id, name, webauthn_expected(), bytes_of(made.client_data_json), bytes_of(made.attestation_object),
                                 kTestDeadline, executor, done);
    });
  }

  lugh::Outcome<lugh::webauthn::Asserted> assert_with(soft_authenticator::Authenticator& authenticator, const std::string& user_id) {
    const auto proof = authenticator.get(kWebAuthnChallenge);
    const std::string id(authenticator.credential_id().begin(), authenticator.credential_id().end());
    return wait_for<lugh::Outcome<lugh::webauthn::Asserted>>([&](lugh::Executor executor, auto done) {
      factors->webauthn_check(user_id, webauthn_expected(), id, bytes_of(proof.client_data_json), bytes_of(proof.authenticator_data), bytes_of(proof.signature),
                              kTestDeadline, executor, done);
    });
  }
};

TEST_F(WebAuthnFactorsTest, ARegisteredCredentialIsASecondFactor) {
  soft_authenticator::Authenticator authenticator;
  EXPECT_FALSE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));
  const auto made = register_with(authenticator, alice.id);
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.kind, FactorKind::webauthn);
  EXPECT_EQ(made.value.name, "laptop");
  EXPECT_EQ(made.value.aaguid, "0102030405060708090a0b0c0d0e0f10");
  EXPECT_EQ(made.value.id.rfind(alice.id + "/webauthn/", 0), 0u);
  EXPECT_TRUE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));

  const auto ids =
      read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) { factors->webauthn_credentials(alice.id, kTestDeadline, executor, done); });
  ASSERT_EQ(ids.size(), 1u);
  EXPECT_EQ(ids[0], std::string(authenticator.credential_id().begin(), authenticator.credential_id().end()));
  EXPECT_TRUE(rig.audited("factor.webauthn.register"));
}

TEST_F(WebAuthnFactorsTest, AnAssertionMovesTheCountAndTheLastUse) {
  soft_authenticator::Authenticator authenticator;
  ASSERT_TRUE(register_with(authenticator, alice.id).ok());
  rig.advance(std::chrono::seconds(100));
  const auto first = assert_with(authenticator, alice.id);
  ASSERT_TRUE(first.ok()) << first.message;
  EXPECT_EQ(first.value.sign_count, 1u);
  const auto listed = read_value<std::vector<FactorInfo>>([&](lugh::Executor executor, auto done) { factors->list(alice.id, kTestDeadline, executor, done); });
  ASSERT_EQ(listed.size(), 1u);
  EXPECT_NE(listed[0].last_used, 0u);

  // The count stored moved: an assertion that repeats it is a clone's.
  authenticator.sign_count = 0;
  EXPECT_EQ(assert_with(authenticator, alice.id).fault, Fault::refused);
  EXPECT_TRUE(assert_with(authenticator, alice.id).ok()) << "2, past the 1 stored";
}

TEST_F(WebAuthnFactorsTest, ACredentialIsOnlyItsOwnersAndOnlyOnce) {
  const auto bob = rig.person("bob");
  soft_authenticator::Authenticator authenticator;
  ASSERT_TRUE(register_with(authenticator, alice.id).ok());
  EXPECT_EQ(register_with(authenticator, alice.id, "again").fault, Fault::duplicate);
  EXPECT_EQ(register_with(authenticator, bob.id).fault, Fault::duplicate) << "registered to anyone";
  EXPECT_EQ(assert_with(authenticator, bob.id).fault, Fault::refused) << "alice's credential, offered for bob";
}

TEST_F(WebAuthnFactorsTest, ACeremonyThatFailsRegistersNothing) {
  soft_authenticator::Authenticator elsewhere;
  elsewhere.origin = "https://evil.example";
  EXPECT_EQ(register_with(elsewhere, alice.id).fault, Fault::refused);
  EXPECT_TRUE(rig.audited("factor.webauthn.register.refused"));
  soft_authenticator::Authenticator unnamed;
  EXPECT_EQ(register_with(unnamed, alice.id, "").fault, Fault::invalid);
  EXPECT_EQ(register_with(unnamed, alice.id, std::string(65, 'n')).fault, Fault::invalid);
  EXPECT_FALSE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));
}

TEST_F(WebAuthnFactorsTest, AResetForgetsCredentials) {
  soft_authenticator::Authenticator authenticator;
  ASSERT_TRUE(register_with(authenticator, alice.id).ok());
  ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { factors->forget(rig.admin, alice.id, kTestDeadline, executor, done); }).ok);
  EXPECT_EQ(assert_with(authenticator, alice.id).fault, Fault::refused);
  EXPECT_TRUE(register_with(authenticator, alice.id).ok()) << "the same authenticator may be registered again after a reset";
}

TEST(WebAuthnRecord, EncodesAndDecodes) {
  WebAuthnRecord record;
  record.created = 1;
  record.last_used = 2;
  record.name = "key";
  record.credential_id = "id";
  record.key.kind = lugh::webauthn::PublicKey::Kind::rs256;
  record.key.modulus = std::string(256, 'n');
  record.key.exponent = std::string("\x01\x00\x01", 3);
  record.sign_count = 7;
  record.backup_eligible = true;
  record.backed_up = true;
  const auto decoded = decode_webauthn(encode(record));
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->key.modulus, record.key.modulus);
  EXPECT_EQ(decoded->sign_count, 7u);
  EXPECT_TRUE(decoded->backed_up);

  record.backup_eligible = false;
  EXPECT_FALSE(decode_webauthn(encode(record))) << "backed up but not eligible is no record";
  record.backed_up = false;
  record.credential_id.clear();
  EXPECT_FALSE(decode_webauthn(encode(record))) << "a credential with no id";
}

// A record under the person's factors that no reader understands (a newer format, or damage) is
// left out of what they are shown, and does not stop the rest from working.
TEST_F(FactorsTest, ARecordThatCannotBeReadIsLeftOut) {
  const auto setup = confirmed_totp();
  const std::vector<unsigned char> unknown_kind{1, 0x7f};
  const std::vector<unsigned char> damaged{1, static_cast<unsigned char>(FactorKind::webauthn), 0xff, 0xff};
  ASSERT_TRUE(rig.store->put_now(Factors::kTable, alice.id + "/totp/0000000000000001", unknown_kind).ok());
  ASSERT_TRUE(rig.store->put_now(Factors::kTable, alice.id + "/webauthn/0000000000000002", damaged).ok());
  const auto listed =
      read_value<std::vector<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) { factors->list(alice.id, kTestDeadline, executor, done); });
  ASSERT_EQ(listed.size(), 1u);
  EXPECT_EQ(listed[0].kind, FactorKind::totp);
  EXPECT_TRUE(read_value<bool>([&](lugh::Executor executor, auto done) { factors->has_second_factor(alice.id, kTestDeadline, executor, done); }));
  EXPECT_TRUE(wait_for<lugh::Outcome<lugh::Nothing>>([&](lugh::Executor executor, auto done) {
                factors->totp_check(alice.id, rig.code_for(setup.secret), kTestDeadline, executor, done);
              }).ok());
}

// Someone who never had recovery codes has none to use.
TEST_F(FactorsTest, NoRecoveryCodesNoneToUse) {
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              factors->recovery_use(alice.id, lugh::text_secret("ABCD-EFGH-JKLM-NPQR"), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
}

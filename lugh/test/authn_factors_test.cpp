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

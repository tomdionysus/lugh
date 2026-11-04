//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/tokens/signing_keys.h"

using lugh::Outcome;
using lugh::Status;
using namespace lugh::tokens;
using std::chrono::hours;

namespace {

class SigningKeysTest : public ::testing::Test {
 protected:
  std::shared_ptr<SigningKeys> opened() {
    auto keys = std::make_shared<SigningKeys>(rig.store, rig.wall, rig.audit, SigningKeys::Settings{});
    const auto status = wait_for<Status>([&](lugh::Executor executor, auto done) { keys->open(kTestDeadline, executor, done); });
    EXPECT_TRUE(status.ok) << status.error;
    return keys;
  }

  Outcome<KeyInfo> rotate(const std::shared_ptr<SigningKeys>& keys, SigningAlgorithm algorithm) {
    return wait_for<Outcome<KeyInfo>>([&](lugh::Executor executor, auto done) { keys->rotate(rig.admin, algorithm, kTestDeadline, executor, done); });
  }

  // Whether a token `keys` signs now verifies against what `keys` publishes now.
  static bool signs_and_verifies(const SigningKeys& keys, SigningAlgorithm algorithm) {
    const auto signer = keys.signer(algorithm);
    if (!signer) return false;
    const auto jws = jws_parse(jws_sign(*signer->key, signer->kid, "at+jwt", boost::json::object{{"sub", "u"}}));
    return jws && jws_verify(*jws, keys.published());
  }

  AuthnRig rig;
};

}  // namespace

// A new cluster's first start makes a key of each algorithm, signing at once.
TEST_F(SigningKeysTest, TheFirstStartMakesAKeyOfEach) {
  const auto keys = opened();
  ASSERT_EQ(keys->keys().size(), 2u);
  EXPECT_TRUE(signs_and_verifies(*keys, SigningAlgorithm::es256));
  EXPECT_TRUE(signs_and_verifies(*keys, SigningAlgorithm::ed25519));
  const auto jwks = keys->jwks();
  ASSERT_EQ(jwks.at("keys").as_array().size(), 2u);
  for (const auto& jwk : jwks.at("keys").as_array()) EXPECT_FALSE(jwk.as_object().contains("d"));
  EXPECT_TRUE(rig.audited("key.create"));
}

// The keys are the store's: a restart signs with the same ones and makes no more.
TEST_F(SigningKeysTest, AStartReadsTheKeysThereAre) {
  const auto first = opened();
  const auto kid = first->signer()->kid;
  const auto token = jws_sign(*first->signer()->key, kid, "at+jwt", boost::json::object{{"sub", "u"}});

  const auto again = opened();
  EXPECT_EQ(again->keys().size(), 2u);
  EXPECT_EQ(again->signer()->kid, kid);
  EXPECT_TRUE(jws_verify(*jws_parse(token), again->published()));
}

// A new key is published before it signs, and the old one stays published until every token
// it signed has expired (docs/architecture.md: "announced in JWKS before any token is signed
// with them").
TEST_F(SigningKeysTest, RotationPublishesFirstAndRetiresLater) {
  const auto keys = opened();
  const auto old_kid = keys->signer()->kid;
  const auto old_token = jws_sign(*keys->signer()->key, old_kid, "at+jwt", boost::json::object{{"sub", "u"}});

  const auto made = rotate(keys, SigningAlgorithm::es256);
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_TRUE(rig.audited("key.rotate"));
  // Published, not yet signing.
  EXPECT_EQ(keys->published().size(), 3u);
  EXPECT_EQ(keys->signer()->kid, old_kid);

  rig.advance(hours(1));
  EXPECT_EQ(keys->signer()->kid, made.value.kid);
  EXPECT_TRUE(signs_and_verifies(*keys, SigningAlgorithm::es256));
  EXPECT_TRUE(jws_verify(*jws_parse(old_token), keys->published()));

  rig.advance(hours(2));
  EXPECT_EQ(keys->published().size(), 2u);
  EXPECT_FALSE(jws_verify(*jws_parse(old_token), keys->published()));
  // Retired, not deleted.
  EXPECT_EQ(keys->keys().size(), 3u);
  // And a restart agrees.
  const auto again = opened();
  EXPECT_EQ(again->signer()->kid, made.value.kid);
  EXPECT_EQ(again->published().size(), 2u);
  // The other algorithm was not touched.
  EXPECT_TRUE(signs_and_verifies(*keys, SigningAlgorithm::ed25519));
}

TEST_F(SigningKeysTest, RotationIsDueAfterNinetyDays) {
  const auto keys = opened();
  const auto due = [&] { return wait_for<Status>([&](lugh::Executor executor, auto done) { keys->rotate_due(kTestDeadline, executor, done); }); };
  ASSERT_TRUE(due().ok);
  EXPECT_EQ(keys->keys().size(), 2u);

  rig.advance(hours(24 * 90));
  ASSERT_TRUE(due().ok);
  EXPECT_EQ(keys->keys().size(), 4u);
  // Not again while the new ones wait to sign.
  ASSERT_TRUE(due().ok);
  EXPECT_EQ(keys->keys().size(), 4u);
}

TEST(SigningKeyRecord, RoundTripsAndRefusesWhatEncodingWouldNotMake) {
  SigningKeys::Record record;
  record.algorithm = SigningAlgorithm::ed25519;
  const auto pkcs8 = SigningKey::generate(SigningAlgorithm::ed25519).to_pkcs8();
  record.pkcs8 = lugh::SecureBuffer(pkcs8.reveal().begin(), pkcs8.reveal().end());
  record.created = 1;
  record.active_from = 2;
  record.retired_at = 3;
  const auto bytes = SigningKeys::encode(record);
  const auto back = SigningKeys::decode(bytes);
  ASSERT_TRUE(back);
  EXPECT_EQ(back->algorithm, SigningAlgorithm::ed25519);
  EXPECT_EQ(back->pkcs8, record.pkcs8);
  EXPECT_EQ(back->retired_at, 3u);

  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(SigningKeys::decode(longer));
  auto algorithm = bytes;
  algorithm[1] = 7;
  EXPECT_FALSE(SigningKeys::decode(algorithm));
}

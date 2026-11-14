//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh_client's DPoP proofs (RFC 9449 section 4.2), checked by the issuer's own checker
// (lugh/oauth/dpop.h): for the method and URL, by the key whose thumbprint (RFC 7638) binds the
// tokens, with the access token's hash for a resource request (section 7), each one fresh.

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/dpop.h"
#include "lugh/client/jose.h"
#include "lugh/oauth/dpop.h"

using namespace lugh::client;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kToken = "https://lugh.example/oauth2/token";

struct Checking {
  dannan::test::SteppedTime time;
  dannan::test::SteppedWall wall{kNow * 1000};
  lugh::oauth::DpopChecker checker{time, wall};
};

}  // namespace

TEST(ClientDpop, AProofIsWhatTheIssuersCheckerTakes) {
  for (const auto algorithm : {SigningAlgorithm::es256, SigningAlgorithm::ed25519}) {
    Checking checking;
    const auto key = SigningKey::generate(algorithm);
    const auto checked = checking.checker.check(dpop_proof(key, "POST", kToken, kNow), "POST", kToken);
    ASSERT_TRUE(checked.ok()) << checked.message;
    EXPECT_EQ(checked.value.jkt, lugh::oauth::jwk_thumbprint({"", algorithm, key.public_key()}));
    EXPECT_EQ(checked.value.htm, "POST");
    EXPECT_EQ(checked.value.htu, kToken);
    // For another method or URL it is no proof.
    EXPECT_FALSE(checking.checker.check(dpop_proof(key, "POST", kToken, kNow), "GET", kToken).ok());
    EXPECT_FALSE(checking.checker.check(dpop_proof(key, "POST", kToken, kNow), "POST", "https://lugh.example/oauth2/par").ok());
  }
}

TEST(ClientDpop, AProofForAResourceCarriesTheTokensHash) {
  Checking checking;
  const auto key = SigningKey::generate(SigningAlgorithm::es256);
  const std::string userinfo = "https://lugh.example/oauth2/userinfo";
  EXPECT_TRUE(checking.checker.check(dpop_proof(key, "GET", userinfo, kNow, "at-1"), "GET", userinfo, "at-1").ok());
  EXPECT_FALSE(checking.checker.check(dpop_proof(key, "GET", userinfo, kNow, "at-1"), "GET", userinfo, "at-2").ok());
  EXPECT_FALSE(checking.checker.check(dpop_proof(key, "GET", userinfo, kNow), "GET", userinfo, "at-1").ok());
}

TEST(ClientDpop, EachProofIsFreshAndCarriesOnlyThePublicKey) {
  Checking checking;
  const auto key = SigningKey::generate(SigningAlgorithm::es256);
  const auto first = dpop_proof(key, "POST", kToken, kNow);
  const auto second = dpop_proof(key, "POST", kToken, kNow);
  EXPECT_NE(first, second);
  EXPECT_TRUE(checking.checker.check(first, "POST", kToken).ok());
  // The issuer refuses a proof it has seen.
  EXPECT_FALSE(checking.checker.check(first, "POST", kToken).ok());
  EXPECT_TRUE(checking.checker.check(second, "POST", kToken).ok());
  const auto jwk = dpop_jwk(key);
  EXPECT_FALSE(jwk.contains("d"));
  EXPECT_FALSE(jwk.contains("kid"));
  EXPECT_EQ(jwk.at("kty").as_string(), "EC");
}

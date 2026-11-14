//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/oauth/dpop.h"
#include "lugh/test/fixtures/dpop_proofs.h"

using namespace lugh::oauth;
using lugh::Fault;

namespace {

constexpr std::uint64_t kNow = 1792281600;
constexpr const char* kUrl = "https://id.example.com/oauth2/token";

struct Checking {
  dannan::test::SteppedTime time;
  dannan::test::SteppedWall wall{kNow * 1000};
  DpopChecker checker{time, wall};
};

}  // namespace

// RFC 9449 section 6.1's key and the jkt it gives.
TEST(Dpop, ThumbprintIsRfc7638) {
  const auto key = lugh::client::from_jwk(
      boost::json::parse(R"({"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"})")
          .as_object());
  ASSERT_TRUE(key);
  EXPECT_EQ(jwk_thumbprint(*key), "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
}

TEST(Dpop, AProofOfEitherAlgorithm) {
  for (const auto algorithm : {lugh::client::SigningAlgorithm::es256, lugh::client::SigningAlgorithm::ed25519}) {
    DpopClient client(algorithm);
    const auto proof = parse_proof(client.proof("POST", kUrl, kNow));
    ASSERT_TRUE(proof);
    EXPECT_EQ(proof->htm, "POST");
    EXPECT_EQ(proof->htu, kUrl);
    EXPECT_EQ(proof->jkt, jwk_thumbprint({"", algorithm, client.key.public_key()}));
  }
}

TEST(Dpop, ProofsLughRefuses) {
  DpopClient client;
  const auto with_d = [&] {
    auto jwk = client.jwk();
    jwk["d"] = "private";
    return jwk;
  }();
  for (const auto& header : {boost::json::object{{"typ", "JWT"}}, boost::json::object{{"kid", "k1"}}, boost::json::object{{"alg", "EdDSA"}},
                             boost::json::object{{"alg", "none"}}, boost::json::object{{"jwk", with_d}}, boost::json::object{{"jwk", "a key"}}}) {
    EXPECT_FALSE(parse_proof(client.proof("POST", kUrl, kNow, std::nullopt, header))) << boost::json::serialize(header);
  }
  for (const auto& claims : {boost::json::object{{"jti", ""}}, boost::json::object{{"iat", "now"}}, boost::json::object{{"htm", 7}}}) {
    EXPECT_FALSE(parse_proof(client.proof("POST", kUrl, kNow, std::nullopt, {}, claims))) << boost::json::serialize(claims);
  }
  // Signed by one key, carrying another.
  DpopClient other;
  EXPECT_FALSE(parse_proof(client.proof("POST", kUrl, kNow, std::nullopt, boost::json::object{{"jwk", other.jwk()}})));
  EXPECT_FALSE(parse_proof("a.b.c"));
}

TEST(Dpop, TheCheckerHoldsAProofToItsRequest) {
  Checking checking;
  DpopClient client;
  EXPECT_TRUE(checking.checker.check(client.proof("POST", kUrl, kNow), "POST", kUrl).ok());
  EXPECT_EQ(checking.checker.check(client.proof("GET", kUrl, kNow), "POST", kUrl).fault, Fault::invalid);
  EXPECT_EQ(checking.checker.check(client.proof("POST", "https://id.example.com/other", kNow), "POST", kUrl).fault, Fault::invalid);
  EXPECT_EQ(checking.checker.check(client.proof("POST", kUrl, kNow - 301), "POST", kUrl).fault, Fault::invalid);
  EXPECT_EQ(checking.checker.check(client.proof("POST", kUrl, kNow + 301), "POST", kUrl).fault, Fault::invalid);
  EXPECT_TRUE(checking.checker.check(client.proof("POST", kUrl, kNow - 299), "POST", kUrl).ok());

  // Used once.
  const auto once = client.proof("POST", kUrl, kNow);
  EXPECT_TRUE(checking.checker.check(once, "POST", kUrl).ok());
  EXPECT_EQ(checking.checker.check(once, "POST", kUrl).fault, Fault::invalid);

  // For an access token, its hash.
  EXPECT_TRUE(checking.checker.check(client.proof("GET", kUrl, kNow, "the.token.itself"), "GET", kUrl, "the.token.itself").ok());
  EXPECT_EQ(checking.checker.check(client.proof("GET", kUrl, kNow, "another.token.here"), "GET", kUrl, "the.token.itself").fault, Fault::invalid);
  EXPECT_EQ(checking.checker.check(client.proof("GET", kUrl, kNow), "GET", kUrl, "the.token.itself").fault, Fault::invalid);
}

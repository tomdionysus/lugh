//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh/client/testing.h, for a consumer's tests: tokens it signs, under the JWKS it gives, are
// checked by a Verifier as Lugh's own are, each kind only as itself.

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/testing.h"
#include "lugh/client/verifier.h"

using namespace lugh::client;
// GoogleTest has a ::testing of its own.
namespace lt = lugh::client::testing;

TEST(ClientTesting, ItsTokensAreCheckedAsAnIssuersAre) {
  constexpr std::uint64_t kNow = 1'800'000'000;
  constexpr const char* kIssuer = "https://lugh.example";
  dannan::test::SteppedWall wall{kNow * 1000};
  Verifier verifier({kIssuer}, wall);
  for (const auto algorithm : {dannan::identity::SigningAlgorithm::es256, dannan::identity::SigningAlgorithm::ed25519}) {
    const auto key = dannan::identity::SigningKey::generate(algorithm);
    EXPECT_EQ(verifier.set_keys(kIssuer, lt::jwks(key, "t1")), 1u);
    const auto access =
        lt::sign_access_token(key, "t1", {{"iss", kIssuer}, {"sub", "u1"}, {"aud", "lir"}, {"client_id", "app1"}, {"exp", kNow + 60}, {"jti", "j1"}});
    const auto checked = verifier.verify_access(access, "lir");
    ASSERT_TRUE(std::holds_alternative<AccessToken>(checked)) << std::get<std::string>(checked);
    EXPECT_EQ(std::get<AccessToken>(checked).subject, "u1");
    const auto id = lt::sign_id_token(key, "t1", {{"iss", kIssuer}, {"sub", "u1"}, {"aud", "app1"}, {"iat", kNow}, {"exp", kNow + 60}});
    EXPECT_TRUE(std::holds_alternative<IdToken>(verifier.verify_id(id, "app1")));
    // Each only as itself.
    EXPECT_FALSE(std::holds_alternative<IdToken>(verifier.verify_id(access, "app1")));
    EXPECT_FALSE(std::holds_alternative<AccessToken>(verifier.verify_access(id)));
  }
}

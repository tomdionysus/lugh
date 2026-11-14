//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh::client::Verifier, as a relying party uses it (TODO/2026-11-14-p10-plan.md, P10.1): several
// trusted issuers, one per site, each with its own keys from a JWKS (RFC 7517 section 5); a token's
// iss picks the keys and its kid the key; refusals that tell a key source to look again; keys
// replaced as they rotate; time from the injected wall clock. ID tokens as OpenID Connect Core
// 1.0 section 3.1.3.7 has a client check them. Keys replaced while tokens are checked.

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/jose.h"
#include "lugh/client/verifier.h"

using namespace lugh::client;
using std::chrono::seconds;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kSiteA = "https://lugh.site-a.example";
constexpr const char* kSiteB = "https://lugh.site-b.example";

// One site's Lugh: a key under a kid, its JWKS, and tokens it signs.
struct Site {
  Site(std::string name, std::string key_id, SigningAlgorithm algorithm = SigningAlgorithm::es256)
      : issuer(std::move(name)), kid(std::move(key_id)), key(SigningKey::generate(algorithm)), algorithm_(algorithm) {}

  boost::json::object jwks() const {
    boost::json::array keys;
    keys.push_back(*public_jwk({kid, algorithm_, key.public_key()}));
    return boost::json::object{{"keys", keys}};
  }

  boost::json::object access_claims() const {
    return {{"iss", issuer}, {"sub", "u1"},       {"aud", "lir"}, {"client_id", "app1"},
            {"iat", kNow},   {"exp", kNow + 300}, {"jti", "j1"},  {"scope", "lir:sub:sensors/%23"}};
  }

  boost::json::object id_claims() const {
    return {{"iss", issuer},     {"sub", "u1"},       {"aud", "app1"},  {"azp", "app1"}, {"iat", kNow},
            {"exp", kNow + 300}, {"auth_time", kNow}, {"nonce", "n-1"}, {"sid", "s1"},   {"acr", "mfa"}};
  }

  std::string sign(const boost::json::object& claims, std::string_view typ) const { return jws_sign(key, kid, typ, claims); }
  std::string access() const { return sign(access_claims(), "at+jwt"); }
  std::string id() const { return sign(id_claims(), "JWT"); }

  std::string issuer;
  std::string kid;
  SigningKey key;
  SigningAlgorithm algorithm_;
};

template <typename Token>
std::string refusal(const std::variant<Token, std::string>& checked) {
  const auto* why = std::get_if<std::string>(&checked);
  return why ? *why : std::string();
}

struct Rig {
  dannan::test::SteppedWall wall{kNow * 1000};
  Site a{kSiteA, "a1"};
  Site b{kSiteB, "b1", SigningAlgorithm::ed25519};
  Verifier verifier{{kSiteA, kSiteB}, wall};

  Rig() {
    verifier.set_keys(kSiteA, a.jwks());
    verifier.set_keys(kSiteB, b.jwks());
  }
};

}  // namespace

TEST(ClientVerifier, NeedsAnIssuerToTrust) {
  dannan::test::SteppedWall wall;
  EXPECT_THROW(Verifier({}, wall), std::invalid_argument);
  EXPECT_THROW(Verifier({kSiteA, ""}, wall), std::invalid_argument);
}

TEST(ClientVerifier, EachSitesTokensAreCheckedWithThatSitesKeys) {
  Rig rig;
  for (const auto* site : {&rig.a, &rig.b}) {
    const auto checked = rig.verifier.verify_access(site->access(), "lir");
    ASSERT_TRUE(std::holds_alternative<AccessToken>(checked)) << refusal(checked);
    EXPECT_EQ(std::get<AccessToken>(checked).issuer, site->issuer);
    EXPECT_EQ(std::get<AccessToken>(checked).scopes, std::vector<std::string>{"lir:sub:sensors/%23"});
  }
  // A token saying it is site B's, signed by site A's key under site B's kid, is not site B's.
  auto claimed = rig.a.access_claims();
  claimed["iss"] = kSiteB;
  EXPECT_EQ(refusal(rig.verifier.verify_access(jws_sign(rig.a.key, "b1", "at+jwt", claimed))), "the signature does not verify");
  // Under site A's kid, site B's keys have no such key.
  EXPECT_EQ(refusal(rig.verifier.verify_access(rig.a.sign(claimed, "at+jwt"))), "no key with its kid");
}

TEST(ClientVerifier, RefusalsSayWhenTheKeysShouldBeLookedForAgain) {
  dannan::test::SteppedWall wall{kNow * 1000};
  const Site a{kSiteA, "a1"};
  Verifier verifier({kSiteA}, wall);
  EXPECT_EQ(refusal(verifier.verify_access(a.access())), "no keys yet for its issuer");
  verifier.set_keys(kSiteA, a.jwks());
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(a.access())));

  // The site rotates to a new key: its tokens name a kid the verifier does not hold until the
  // new JWKS is set, and then the old key is no longer trusted.
  const Site rotated{kSiteA, "a2"};
  EXPECT_EQ(refusal(verifier.verify_access(rotated.access())), "no key with its kid");
  EXPECT_EQ(verifier.set_keys(kSiteA, rotated.jwks()), 1u);
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(rotated.access())));
  EXPECT_EQ(refusal(verifier.verify_access(a.access())), "no key with its kid");

  const Site stranger{"https://elsewhere.example", "a1"};
  EXPECT_EQ(refusal(verifier.verify_access(stranger.access())), "not from an issuer trusted");
  EXPECT_EQ(refusal(verifier.verify_access("garbage")), "not a JWS Lugh reads");
}

TEST(ClientVerifier, AJwksIsTakenForWhatItHolds) {
  Rig rig;
  EXPECT_THROW(rig.verifier.set_keys("https://elsewhere.example", rig.a.jwks()), std::invalid_argument);
  EXPECT_THROW(rig.verifier.set_keys(kSiteA, boost::json::object{}), std::runtime_error);
  EXPECT_THROW(rig.verifier.set_keys(kSiteA, boost::json::object{{"keys", "a1"}}), std::runtime_error);
  boost::json::array many;
  for (std::size_t i = 0; i <= Verifier::kMostKeys; ++i) many.push_back(rig.a.jwks().at("keys").as_array().at(0));
  EXPECT_THROW(rig.verifier.set_keys(kSiteA, boost::json::object{{"keys", many}}), std::runtime_error);
  // A refused document leaves the keys as they were.
  EXPECT_TRUE(std::holds_alternative<AccessToken>(rig.verifier.verify_access(rig.a.access())));

  // Keys Lugh does not sign with, a key with no kid, and an entry that is no object are skipped.
  auto usable = rig.a.jwks().at("keys").as_array().at(0).as_object();
  auto no_kid = usable;
  no_kid.erase("kid");
  const boost::json::array mixed{boost::json::object{{"kty", "RSA"}, {"kid", "r1"}, {"n", "AQAB"}, {"e", "AQAB"}}, no_kid, "a1", usable};
  EXPECT_EQ(rig.verifier.set_keys(kSiteA, boost::json::object{{"keys", mixed}}), 1u);
  EXPECT_TRUE(std::holds_alternative<AccessToken>(rig.verifier.verify_access(rig.a.access())));
  // A JWKS with nothing usable leaves the issuer with no keys.
  EXPECT_EQ(rig.verifier.set_keys(kSiteA, boost::json::object{{"keys", boost::json::array{}}}), 0u);
  EXPECT_EQ(refusal(rig.verifier.verify_access(rig.a.access())), "no keys yet for its issuer");
}

TEST(ClientVerifier, TimeIsTheWallClocks) {
  Rig rig;
  const auto token = rig.a.access();
  rig.wall.advance(seconds(300 + kClockSkewSeconds - 1));
  EXPECT_TRUE(std::holds_alternative<AccessToken>(rig.verifier.verify_access(token)));
  rig.wall.advance(seconds(1));
  EXPECT_EQ(refusal(rig.verifier.verify_access(token)), "expired");
  EXPECT_EQ(refusal(rig.verifier.verify_id(rig.a.id(), "app1")), "expired");
}

TEST(ClientVerifier, AnIdTokenForThisClient) {
  Rig rig;
  for (const auto* site : {&rig.a, &rig.b}) {
    const auto checked = rig.verifier.verify_id(site->id(), "app1", "n-1");
    ASSERT_TRUE(std::holds_alternative<IdToken>(checked)) << refusal(checked);
    const auto& token = std::get<IdToken>(checked);
    EXPECT_EQ(token.issuer, site->issuer);
    EXPECT_EQ(token.subject, "u1");
    EXPECT_EQ(token.audiences, std::vector<std::string>{"app1"});
    EXPECT_EQ(token.expires, kNow + 300);
    EXPECT_EQ(token.issued_at, kNow);
    EXPECT_EQ(token.auth_time, kNow);
    EXPECT_EQ(token.nonce, "n-1");
    EXPECT_EQ(token.sid, "s1");
    EXPECT_EQ(token.acr, "mfa");
  }
  // With no nonce asked for, any or none will do.
  EXPECT_TRUE(std::holds_alternative<IdToken>(rig.verifier.verify_id(rig.a.id(), "app1")));
}

TEST(ClientVerifier, AnIdTokenIsRefusedForWhatTheClientMustCheck) {
  Rig rig;
  const auto& a = rig.a;
  EXPECT_EQ(refusal(rig.verifier.verify_id(a.id(), "app2")), "not for this client");
  EXPECT_EQ(refusal(rig.verifier.verify_id(a.id(), "app1", "n-2")), "not the nonce sent");
  // An access token is never taken for an ID token, nor the other way.
  EXPECT_EQ(refusal(rig.verifier.verify_id(a.access(), "app1")), "not an ID token (typ is not JWT)");
  EXPECT_EQ(refusal(rig.verifier.verify_access(a.id())), "not an access token (typ is not at+jwt)");

  auto several = a.id_claims();
  several["aud"] = boost::json::array{"app1", "app2"};
  several.erase("azp");
  EXPECT_EQ(refusal(rig.verifier.verify_id(a.sign(several, "JWT"), "app1")), "several audiences and no azp");
  several["azp"] = "app1";
  EXPECT_TRUE(std::holds_alternative<IdToken>(rig.verifier.verify_id(a.sign(several, "JWT"), "app1")));
  auto other_azp = a.id_claims();
  other_azp["azp"] = "app2";
  EXPECT_EQ(refusal(rig.verifier.verify_id(a.sign(other_azp, "JWT"), "app1")), "azp is another client");

  for (const auto* name : {"sub", "exp", "iat"}) {
    auto missing = a.id_claims();
    missing.erase(name);
    EXPECT_NE(refusal(rig.verifier.verify_id(a.sign(missing, "JWT"), "app1")), "") << name;
  }
  auto missing_nonce = a.id_claims();
  missing_nonce.erase("nonce");
  EXPECT_EQ(refusal(rig.verifier.verify_id(a.sign(missing_nonce, "JWT"), "app1", "n-1")), "not the nonce sent");
}

// Tokens are checked on several threads while the keys are replaced on another; every answer is
// one of the two key sets', never a torn one.
TEST(ClientVerifier, KeysAreReplacedWhileTokensAreChecked) {
  dannan::test::SteppedWall wall{kNow * 1000};
  const Site first{kSiteA, "a1"};
  const Site second{kSiteA, "a2"};
  Verifier verifier({kSiteA}, wall);
  verifier.set_keys(kSiteA, first.jwks());
  const auto token = first.access();

  std::atomic<bool> stop{false};
  std::atomic<int> unexpected{0};
  std::vector<std::thread> checkers;
  for (int i = 0; i < 3; ++i) {
    checkers.emplace_back([&] {
      while (!stop.load()) {
        const auto checked = verifier.verify_access(token);
        if (!std::holds_alternative<AccessToken>(checked) && refusal(checked) != "no key with its kid") ++unexpected;
      }
    });
  }
  for (int i = 0; i < 200; ++i) verifier.set_keys(kSiteA, (i % 2 == 0 ? second : first).jwks());
  stop = true;
  for (auto& checker : checkers) checker.join();
  EXPECT_EQ(unexpected.load(), 0);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// An access token checked offline, as a relying party checks it (RFC 9068 section 4): typ
// at+jwt, the signature by the key the kid names, iss, sub, client_id and jti, exp and nbf with
// a clock's skew, the audience, and a cnf that binds to a key or a certificate (RFC 9449, RFC
// 8705). Each refusal says why.

#include <gtest/gtest.h>

#include <array>

#include "lugh/client/access_token.h"
#include "lugh/core/encoding.h"

using namespace lugh::client;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kIssuer = "https://lugh.example";

struct Signer {
  explicit Signer(SigningAlgorithm algorithm = SigningAlgorithm::es256) : key(SigningKey::generate(algorithm)), keys{{"k1", algorithm, key.public_key()}} {}

  std::string sign(const boost::json::object& claims, std::string_view typ = "at+jwt", const std::string& kid = "k1") const {
    return jws_sign(key, kid, typ, claims);
  }

  SigningKey key;
  std::vector<VerifyKey> keys;
};

boost::json::object claims() {
  return boost::json::object{{"iss", kIssuer},      {"sub", "u1"}, {"aud", boost::json::array{"lir", "https://lugh.example/userinfo"}},
                             {"client_id", "app1"}, {"iat", kNow}, {"nbf", kNow},
                             {"exp", kNow + 300},   {"jti", "j1"}, {"scope", "openid lir:sub:a/%2B"}};
}

std::string refusal(const std::variant<AccessToken, std::string>& checked) {
  const auto* why = std::get_if<std::string>(&checked);
  return why ? *why : std::string();
}

}  // namespace

TEST(ClientAccessToken, ATokenLughIssuesIsReadBack) {
  for (const auto algorithm : {SigningAlgorithm::es256, SigningAlgorithm::ed25519}) {
    const Signer signer(algorithm);
    const auto checked = check_access_token(signer.sign(claims()), signer.keys, kIssuer, kNow, "lir");
    const auto* token = std::get_if<AccessToken>(&checked);
    ASSERT_TRUE(token) << refusal(checked);
    EXPECT_EQ(token->issuer, kIssuer);
    EXPECT_EQ(token->subject, "u1");
    EXPECT_EQ(token->client_id, "app1");
    EXPECT_EQ(token->jti, "j1");
    EXPECT_EQ(token->audiences, (std::vector<std::string>{"lir", "https://lugh.example/userinfo"}));
    EXPECT_EQ(token->scopes, (std::vector<std::string>{"openid", "lir:sub:a/%2B"}));
    EXPECT_EQ(token->expires, kNow + 300);
    EXPECT_FALSE(token->jkt);
    EXPECT_FALSE(token->x5t);
    EXPECT_EQ(token->claims.at("sub"), "u1");
  }
}

TEST(ClientAccessToken, WhatIsNotASignedAccessTokenIsRefused) {
  const Signer signer;
  EXPECT_EQ(refusal(check_access_token("not.a.jws", signer.keys, kIssuer, kNow)), "not a JWS Lugh reads");
  EXPECT_EQ(refusal(check_access_token("", signer.keys, kIssuer, kNow)), "not a JWS Lugh reads");
  // An ID token is a JWT of Lugh's, but not an access token.
  EXPECT_EQ(refusal(check_access_token(signer.sign(claims(), "JWT"), signer.keys, kIssuer, kNow)), "not an access token (typ is not at+jwt)");
  // Signed by a key that is not among those given, under a kid that is, and under one that is not.
  const Signer other;
  EXPECT_EQ(refusal(check_access_token(other.sign(claims()), signer.keys, kIssuer, kNow)), "the signature does not verify");
  EXPECT_EQ(refusal(check_access_token(signer.sign(claims(), "at+jwt", "k2"), signer.keys, kIssuer, kNow)), "the signature does not verify");
  // No keys at all.
  EXPECT_EQ(refusal(check_access_token(signer.sign(claims()), {}, kIssuer, kNow)), "the signature does not verify");
}

TEST(ClientAccessToken, AnotherIssuersTokenIsRefused) {
  const Signer signer;
  auto other = claims();
  other["iss"] = "https://other.example";
  EXPECT_EQ(refusal(check_access_token(signer.sign(other), signer.keys, kIssuer, kNow)), "not this issuer's");
  other.erase("iss");
  EXPECT_EQ(refusal(check_access_token(signer.sign(other), signer.keys, kIssuer, kNow)), "not this issuer's");
}

TEST(ClientAccessToken, SubClientIdAndJtiAreRequired) {
  const Signer signer;
  for (const auto* name : {"sub", "client_id"}) {
    auto missing = claims();
    missing.erase(name);
    EXPECT_EQ(refusal(check_access_token(signer.sign(missing), signer.keys, kIssuer, kNow)), "no sub or client_id") << name;
    auto number = claims();
    number[name] = 7;
    EXPECT_EQ(refusal(check_access_token(signer.sign(number), signer.keys, kIssuer, kNow)), "no sub or client_id") << name;
  }
  auto missing = claims();
  missing.erase("jti");
  EXPECT_EQ(refusal(check_access_token(signer.sign(missing), signer.keys, kIssuer, kNow)), "no jti");
}

TEST(ClientAccessToken, ItsLifetimeHasAClocksSkewEitherSide) {
  const Signer signer;
  const auto token = signer.sign(claims());
  const auto exp = kNow + 300;
  EXPECT_TRUE(std::holds_alternative<AccessToken>(check_access_token(token, signer.keys, kIssuer, exp + kClockSkewSeconds - 1)));
  EXPECT_EQ(refusal(check_access_token(token, signer.keys, kIssuer, exp + kClockSkewSeconds)), "expired");
  EXPECT_TRUE(std::holds_alternative<AccessToken>(check_access_token(token, signer.keys, kIssuer, kNow - kClockSkewSeconds)));
  EXPECT_EQ(refusal(check_access_token(token, signer.keys, kIssuer, kNow - kClockSkewSeconds - 1)), "not yet valid");

  auto no_exp = claims();
  no_exp.erase("exp");
  EXPECT_EQ(refusal(check_access_token(signer.sign(no_exp), signer.keys, kIssuer, kNow)), "no exp");
  auto negative = claims();
  negative["exp"] = -1;
  EXPECT_EQ(refusal(check_access_token(signer.sign(negative), signer.keys, kIssuer, kNow)), "no exp");
  // nbf is optional.
  auto no_nbf = claims();
  no_nbf.erase("nbf");
  EXPECT_TRUE(std::holds_alternative<AccessToken>(check_access_token(signer.sign(no_nbf), signer.keys, kIssuer, kNow - 1000)));
}

TEST(ClientAccessToken, TheAudienceAskedForMustBeAmongItsAudiences) {
  const Signer signer;
  EXPECT_EQ(refusal(check_access_token(signer.sign(claims()), signer.keys, kIssuer, kNow, "macha")), "not for this audience");
  // aud as one string.
  auto single = claims();
  single["aud"] = "lir";
  const auto checked = check_access_token(signer.sign(single), signer.keys, kIssuer, kNow, "lir");
  ASSERT_TRUE(std::holds_alternative<AccessToken>(checked)) << refusal(checked);
  EXPECT_EQ(std::get<AccessToken>(checked).audiences, std::vector<std::string>{"lir"});
  // No audience asked for: any will do, none included.
  auto none = claims();
  none.erase("aud");
  EXPECT_TRUE(std::holds_alternative<AccessToken>(check_access_token(signer.sign(none), signer.keys, kIssuer, kNow)));
  EXPECT_EQ(refusal(check_access_token(signer.sign(none), signer.keys, kIssuer, kNow, "lir")), "not for this audience");
}

TEST(ClientAccessToken, ACnfBindsToAKeyOrACertificateOrIsRefused) {
  const Signer signer;
  auto to_key = claims();
  to_key["cnf"] = boost::json::object{{"jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}};
  const auto key_bound = check_access_token(signer.sign(to_key), signer.keys, kIssuer, kNow);
  ASSERT_TRUE(std::holds_alternative<AccessToken>(key_bound)) << refusal(key_bound);
  EXPECT_EQ(std::get<AccessToken>(key_bound).jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");

  // RFC 8705 3.1: the certificate's SHA-256, base64url; carried decoded.
  std::array<std::uint8_t, 32> thumbprint{};
  for (std::size_t i = 0; i < thumbprint.size(); ++i) thumbprint[i] = static_cast<std::uint8_t>(i * 7 + 1);
  auto to_certificate = claims();
  to_certificate["cnf"] = boost::json::object{{"x5t#S256", lugh::encoding::base64url(thumbprint)}};
  const auto certificate_bound = check_access_token(signer.sign(to_certificate), signer.keys, kIssuer, kNow);
  ASSERT_TRUE(std::holds_alternative<AccessToken>(certificate_bound)) << refusal(certificate_bound);
  EXPECT_EQ(std::get<AccessToken>(certificate_bound).x5t, thumbprint);
  // A thumbprint that is not base64url of 32 bytes binds to nothing.
  for (const auto* bad : {"not base64url!", "AAAA", "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2A"}) {
    auto malformed = claims();
    malformed["cnf"] = boost::json::object{{"x5t#S256", bad}};
    EXPECT_EQ(refusal(check_access_token(signer.sign(malformed), signer.keys, kIssuer, kNow)), "bound to a certificate thumbprint that is not one") << bad;
  }

  for (const auto& cnf : {boost::json::object{}, boost::json::object{{"jwk", "x"}}, boost::json::object{{"jkt", 7}}}) {
    auto unknown = claims();
    unknown["cnf"] = cnf;
    EXPECT_EQ(refusal(check_access_token(signer.sign(unknown), signer.keys, kIssuer, kNow)), "bound to something not known") << boost::json::serialize(cnf);
  }
}

TEST(ClientAccessToken, ScopesAreSplitOnSpaces) {
  const Signer signer;
  auto spaced = claims();
  spaced["scope"] = " openid  profile ";
  const auto checked = check_access_token(signer.sign(spaced), signer.keys, kIssuer, kNow);
  ASSERT_TRUE(std::holds_alternative<AccessToken>(checked)) << refusal(checked);
  EXPECT_EQ(std::get<AccessToken>(checked).scopes, (std::vector<std::string>{"openid", "profile"}));
  auto none = claims();
  none.erase("scope");
  EXPECT_TRUE(std::get<AccessToken>(check_access_token(signer.sign(none), signer.keys, kIssuer, kNow)).scopes.empty());
}

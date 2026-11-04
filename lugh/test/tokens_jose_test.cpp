//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/core/encoding.h"
#include "lugh/tokens/jose.h"

using namespace lugh::tokens;
using dannan::identity::SigningAlgorithm;
using lugh::byte_span;

namespace {

boost::json::object parsed(const char* json) { return boost::json::parse(json).as_object(); }

// The JWS of `header` and `claims` as given, signed by `key`: for building tokens Lugh would
// never make.
std::string forged(const SigningKey& key, const std::string& header, const std::string& claims) {
  const auto input = lugh::encoding::base64url(byte_span(header)) + "." + lugh::encoding::base64url(byte_span(claims));
  return input + "." + lugh::encoding::base64url(key.sign(byte_span(input)));
}

}  // namespace

// RFC 7515 appendix A.3: an ES256 JWS and the P-256 public key that verifies it, as a JWK.
TEST(Jose, Rfc7515AppendixA3) {
  const auto key =
      from_jwk(parsed(R"({"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"})"));
  ASSERT_TRUE(key);
  EXPECT_EQ(key->algorithm, SigningAlgorithm::es256);
  const std::string input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
  const auto signature = lugh::encoding::base64url_decode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
  ASSERT_TRUE(signature);
  EXPECT_TRUE(dannan::identity::verify(SigningAlgorithm::es256, key->public_key, byte_span(input), *signature));
  auto other = input;
  other.back() = 'R';
  EXPECT_FALSE(dannan::identity::verify(SigningAlgorithm::es256, key->public_key, byte_span(other), *signature));
}

// RFC 8037 appendix A.4: an EdDSA JWS and the Ed25519 public key that verifies it.
TEST(Jose, Rfc8037AppendixA4) {
  const auto key = from_jwk(parsed(R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})"));
  ASSERT_TRUE(key);
  EXPECT_EQ(key->algorithm, SigningAlgorithm::ed25519);
  const std::string input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
  const auto signature = lugh::encoding::base64url_decode("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");
  ASSERT_TRUE(signature);
  EXPECT_TRUE(dannan::identity::verify(SigningAlgorithm::ed25519, key->public_key, byte_span(input), *signature));
}

TEST(Jose, PublicJwksRoundTrip) {
  for (const auto algorithm : {SigningAlgorithm::es256, SigningAlgorithm::ed25519}) {
    const auto key = SigningKey::generate(algorithm);
    const VerifyKey verify{"k1", algorithm, key.public_key()};
    const auto jwk = public_jwk(verify);
    ASSERT_TRUE(jwk);
    EXPECT_EQ(jwk->at("kid"), "k1");
    EXPECT_EQ(jwk->at("use"), "sig");
    EXPECT_EQ(jwk->at("alg"), algorithm == SigningAlgorithm::es256 ? "ES256" : "EdDSA");
    EXPECT_FALSE(jwk->contains("d"));
    const auto back = from_jwk(*jwk);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->public_key, verify.public_key);
    EXPECT_EQ(back->kid, "k1");
  }
}

TEST(Jose, JwksThatAreNotPublicP256OrEd25519Keys) {
  for (const auto* json :
       {R"({"kty":"RSA","n":"AQAB","e":"AQAB"})",
        R"({"kty":"EC","crv":"P-384","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"})",
        R"({"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"})",
        R"({"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})",
        R"({"kty":"OKP","crv":"Ed25519","x":"short"})", R"({"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})",
        R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"})",
        R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","alg":"ES256"})"}) {
    EXPECT_FALSE(from_jwk(parsed(json))) << json;
  }
}

TEST(Jose, SignParseVerify) {
  for (const auto algorithm : {SigningAlgorithm::es256, SigningAlgorithm::ed25519}) {
    const auto key = SigningKey::generate(algorithm);
    const std::vector<VerifyKey> keys{{"k1", algorithm, key.public_key()}};
    const auto token = jws_sign(key, "k1", "at+jwt", parsed(R"({"sub":"u1","scope":"openid"})"));
    const auto jws = jws_parse(token);
    ASSERT_TRUE(jws);
    EXPECT_EQ(jws->kid, "k1");
    EXPECT_EQ(jws->typ, "at+jwt");
    EXPECT_EQ(jws->algorithm, algorithm);
    EXPECT_EQ(jws->claims.at("sub"), "u1");
    EXPECT_TRUE(jws_verify(*jws, keys));

    // Another key with the same kid, or none with it, does not verify.
    const auto other = SigningKey::generate(algorithm);
    EXPECT_FALSE(jws_verify(*jws, {{"k1", algorithm, other.public_key()}}));
    EXPECT_FALSE(jws_verify(*jws, {{"k2", algorithm, key.public_key()}}));

    // Any change to what was signed breaks it.
    auto tampered = token;
    const auto dot = tampered.find('.');
    tampered[dot + 2] = tampered[dot + 2] == 'A' ? 'B' : 'A';
    const auto changed = jws_parse(tampered);
    EXPECT_TRUE(!changed || !jws_verify(*changed, keys));
  }
}

// The algorithm is the key's, never the token's to choose.
TEST(Jose, AlgorithmConfusionIsRefused) {
  const auto es = SigningKey::generate(SigningAlgorithm::es256);
  const auto ed = SigningKey::generate(SigningAlgorithm::ed25519);
  // Signed with the Ed25519 key but claiming the ES256 key's kid.
  const auto lying = forged(ed, R"({"alg":"EdDSA","kid":"es"})", R"({"sub":"u"})");
  const auto jws = jws_parse(lying);
  ASSERT_TRUE(jws);
  EXPECT_FALSE(jws_verify(*jws, {{"es", SigningAlgorithm::es256, es.public_key()}}));
}

TEST(Jose, ParseRefusesWhatLughNeverMakes) {
  const auto key = SigningKey::generate(SigningAlgorithm::es256);
  for (const auto* header : {R"({"alg":"none","kid":"k"})", R"({"alg":"HS256","kid":"k"})", R"({"alg":"RS256","kid":"k"})", R"({"alg":"ES256"})",
                             R"({"alg":"ES256","kid":""})", R"({"alg":"ES256","kid":"k","crit":["exp"]})", R"({"alg":"ES256","kid":"k","jku":"https://x"})",
                             R"({"alg":"ES256","kid":"k","jwk":{}})", R"({"alg":"ES256","kid":"k","typ":7})", R"(["ES256"])"}) {
    EXPECT_FALSE(jws_parse(forged(key, header, R"({"sub":"u"})"))) << header;
  }
  EXPECT_FALSE(jws_parse(forged(key, R"({"alg":"ES256","kid":"k"})", R"("not an object")")));
  for (const auto* text : {"", "a.b", "a.b.c.d", "e30.e30.", "e30.e30.AAAA", "!!.e30.AAAA"}) EXPECT_FALSE(jws_parse(text)) << text;
  EXPECT_FALSE(jws_parse(std::string(kMostJwsBytes + 1, 'a')));
}

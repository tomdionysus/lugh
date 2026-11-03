//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "crypto/signing.h"

#include <gtest/gtest.h>

#include "helpers/hex.h"

using lugh::crypto::SignatureAlgorithm;
using lugh::crypto::SigningKey;
using lugh::crypto::VerifyKey;

namespace {

// RFC 8410's PKCS#8 wrapping of an Ed25519 seed: the fixed prefix, then the 32 bytes.
lugh::Bytes ed25519_pkcs8(const lugh::Bytes& seed) {
  auto der = from_hex("302e020100300506032b657004220420");
  der.insert(der.end(), seed.begin(), seed.end());
  return der;
}

const SignatureAlgorithm kBoth[] = {SignatureAlgorithm::es256, SignatureAlgorithm::ed25519};

}  // namespace

TEST(Signing, JoseNames) {
  EXPECT_EQ(lugh::crypto::jose_name(SignatureAlgorithm::es256), "ES256");
  EXPECT_EQ(lugh::crypto::jose_name(SignatureAlgorithm::ed25519), "EdDSA");
}

// RFC 8032, section 7.1, tests 1 and 2.
TEST(Signing, Ed25519KnownAnswers) {
  struct Vector {
    const char* seed;
    const char* public_key;
    const char* message;
    const char* signature;
  };
  const Vector vectors[] = {
      {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
       "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
      {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
       "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
  };

  for (const auto& vector : vectors) {
    const auto key = SigningKey::from_pkcs8(SignatureAlgorithm::ed25519, ed25519_pkcs8(from_hex(vector.seed)));
    ASSERT_TRUE(key.ok) << key.error;
    EXPECT_EQ(to_hex(key.value.verify_key().public_key()), vector.public_key);

    const auto signature = key.value.sign(from_hex(vector.message));
    ASSERT_TRUE(signature.ok) << signature.error;
    EXPECT_EQ(to_hex(signature.value), vector.signature);

    const auto verify = VerifyKey::from_public(SignatureAlgorithm::ed25519, from_hex(vector.public_key));
    ASSERT_TRUE(verify.ok) << verify.error;
    EXPECT_TRUE(verify.value.verify(from_hex(vector.message), from_hex(vector.signature)));
  }
}

// RFC 6979, appendix A.2.5: P-256 with SHA-256, message "sample". ECDSA signing is
// randomised here, so the known answer is for verifying.
TEST(Signing, Es256VerifiesAKnownSignature) {
  const auto point = from_hex(
      "04"
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
  const auto signature = from_hex(
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");

  const auto key = VerifyKey::from_public(SignatureAlgorithm::es256, point);
  ASSERT_TRUE(key.ok) << key.error;
  EXPECT_EQ(to_hex(key.value.public_key()), to_hex(point));
  EXPECT_TRUE(key.value.verify(lugh::byte_span("sample"), signature));
  EXPECT_FALSE(key.value.verify(lugh::byte_span("samplf"), signature));
}

TEST(Signing, SignThenVerify) {
  for (const auto algorithm : kBoth) {
    const auto key = SigningKey::generate(algorithm);
    ASSERT_TRUE(key.ok) << key.error;
    EXPECT_EQ(key.value.algorithm(), algorithm);

    const auto signature = key.value.sign(lugh::byte_span("header.payload"));
    ASSERT_TRUE(signature.ok) << signature.error;
    EXPECT_EQ(signature.value.size(), 64u);
    EXPECT_TRUE(key.value.verify_key().verify(lugh::byte_span("header.payload"), signature.value));
  }
}

TEST(Signing, RefusesAnythingButTheSignature) {
  for (const auto algorithm : kBoth) {
    const auto key = SigningKey::generate(algorithm).value;
    const auto other = SigningKey::generate(algorithm).value;
    const auto signature = key.sign(lugh::byte_span("message")).value;
    const auto verify = key.verify_key();

    EXPECT_FALSE(verify.verify(lugh::byte_span("messagf"), signature));
    EXPECT_FALSE(other.verify_key().verify(lugh::byte_span("message"), signature));
    for (std::size_t i = 0; i < signature.size(); ++i) {
      auto edited = signature;
      edited[i] ^= 1;
      EXPECT_FALSE(verify.verify(lugh::byte_span("message"), edited)) << i;
    }
    EXPECT_FALSE(verify.verify(lugh::byte_span("message"), std::span(signature).first(63)));
    EXPECT_FALSE(verify.verify(lugh::byte_span("message"), {}));
    EXPECT_FALSE(verify.verify(lugh::byte_span("message"), lugh::Bytes(64, 0)));
  }
}

TEST(Signing, Pkcs8RoundTrip) {
  for (const auto algorithm : kBoth) {
    const auto key = SigningKey::generate(algorithm).value;
    const auto der = key.pkcs8();
    ASSERT_TRUE(der.ok) << der.error;

    const auto back = SigningKey::from_pkcs8(algorithm, der.value);
    ASSERT_TRUE(back.ok) << back.error;
    EXPECT_EQ(to_hex(back.value.verify_key().public_key()), to_hex(key.verify_key().public_key()));

    const auto signature = back.value.sign(lugh::byte_span("m")).value;
    EXPECT_TRUE(key.verify_key().verify(lugh::byte_span("m"), signature));
  }
}

TEST(Signing, Pkcs8OfTheWrongKindIsRefused) {
  const auto es256 = SigningKey::generate(SignatureAlgorithm::es256).value.pkcs8().value;
  const auto ed25519 = SigningKey::generate(SignatureAlgorithm::ed25519).value.pkcs8().value;
  EXPECT_FALSE(SigningKey::from_pkcs8(SignatureAlgorithm::ed25519, es256).ok);
  EXPECT_FALSE(SigningKey::from_pkcs8(SignatureAlgorithm::es256, ed25519).ok);

  auto trailing = lugh::Bytes(ed25519.begin(), ed25519.end());
  trailing.push_back(0);
  EXPECT_FALSE(SigningKey::from_pkcs8(SignatureAlgorithm::ed25519, trailing).ok);
  EXPECT_FALSE(SigningKey::from_pkcs8(SignatureAlgorithm::ed25519, lugh::Bytes{0x30, 0x00}).ok);
  EXPECT_FALSE(SigningKey::from_pkcs8(SignatureAlgorithm::ed25519, {}).ok);
}

TEST(Signing, PublicKeyRoundTrip) {
  for (const auto algorithm : kBoth) {
    const auto key = SigningKey::generate(algorithm).value;
    const auto raw = key.verify_key().public_key();
    EXPECT_EQ(raw.size(), algorithm == SignatureAlgorithm::es256 ? 65u : 32u);

    const auto verify = VerifyKey::from_public(algorithm, raw);
    ASSERT_TRUE(verify.ok) << verify.error;
    EXPECT_TRUE(verify.value.verify(lugh::byte_span("m"), key.sign(lugh::byte_span("m")).value));
  }
}

TEST(Signing, RefusesPublicKeysThatAreNot) {
  EXPECT_FALSE(VerifyKey::from_public(SignatureAlgorithm::ed25519, lugh::Bytes(31, 1)).ok);

  // The right length, but not a point on the curve.
  auto off_curve = lugh::Bytes(65, 0);
  off_curve[0] = 0x04;
  off_curve[32] = 1;
  off_curve[64] = 1;
  EXPECT_FALSE(VerifyKey::from_public(SignatureAlgorithm::es256, off_curve).ok);

  // Compressed points are not what a JWK gives.
  const auto key = SigningKey::generate(SignatureAlgorithm::es256).value.verify_key().public_key();
  auto compressed = lugh::Bytes(key.begin(), key.begin() + 33);
  compressed[0] = 0x02;
  EXPECT_FALSE(VerifyKey::from_public(SignatureAlgorithm::es256, compressed).ok);
}

TEST(Signing, AnEmptyKeyDoesNothing) {
  const SigningKey empty;
  EXPECT_FALSE(empty.sign(lugh::byte_span("m")).ok);
  EXPECT_FALSE(empty.pkcs8().ok);
  EXPECT_FALSE(empty.verify_key().verify(lugh::byte_span("m"), lugh::Bytes(64, 0)));
  EXPECT_TRUE(empty.verify_key().public_key().empty());
}

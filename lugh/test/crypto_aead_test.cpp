//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "crypto/aead.h"

#include <gtest/gtest.h>

#include "fakes/fixed_random.h"
#include "helpers/hex.h"

namespace crypto = lugh::crypto;

namespace {

const lugh::Bytes kKey = from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

}  // namespace

// The GCM specification's test cases 13, 14 and 16 (McGrew and Viega), AES-256.
TEST(Aead, KnownAnswerEmptyPlaintext) {
  const auto out = crypto::aes256gcm_encrypt(lugh::Bytes(32, 0), lugh::Bytes(12, 0), {}, {});
  ASSERT_TRUE(out.ok) << out.error;
  EXPECT_EQ(to_hex(out.value), "530f8afbc74536b9a963b4f1c4cb738b");
}

TEST(Aead, KnownAnswerOneBlock) {
  const auto out = crypto::aes256gcm_encrypt(lugh::Bytes(32, 0), lugh::Bytes(12, 0), lugh::Bytes(16, 0), {});
  ASSERT_TRUE(out.ok) << out.error;
  EXPECT_EQ(to_hex(out.value), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
}

TEST(Aead, KnownAnswerWithAssociatedData) {
  const auto nonce = from_hex("cafebabefacedbaddecaf888");
  const auto plaintext = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
  const auto associated = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");

  const auto out = crypto::aes256gcm_encrypt(kKey, nonce, plaintext, associated);
  ASSERT_TRUE(out.ok) << out.error;
  EXPECT_EQ(to_hex(out.value),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
            "76fc6ece0f4e1768cddf8853bb2d551b");

  const auto back = crypto::aes256gcm_decrypt(kKey, nonce, out.value, associated);
  ASSERT_TRUE(back);
  EXPECT_EQ(to_hex(*back), to_hex(plaintext));
}

TEST(Aead, SealThenOpen) {
  FixedRandom random;
  const auto plaintext = lugh::byte_span("a record");
  const auto associated = lugh::byte_span("users/alice/3");

  const auto sealed = crypto::seal(kKey, plaintext, associated, random);
  ASSERT_TRUE(sealed.ok) << sealed.error;
  EXPECT_EQ(sealed.value.size(), plaintext.size() + crypto::kAeadOverhead);

  // The nonce is the random port's, in front.
  EXPECT_EQ(to_hex(std::span(sealed.value).first(12)), "000102030405060708090a0b");

  const auto opened = crypto::open(kKey, sealed.value, associated);
  ASSERT_TRUE(opened);
  EXPECT_EQ(std::string(opened->begin(), opened->end()), "a record");
}

TEST(Aead, EachSealHasItsOwnNonce) {
  FixedRandom random;
  const auto first = crypto::seal(kKey, lugh::byte_span("same"), {}, random);
  const auto second = crypto::seal(kKey, lugh::byte_span("same"), {}, random);
  EXPECT_NE(first.value, second.value);
}

TEST(Aead, RefusesTheWrongKey) {
  FixedRandom random;
  const auto sealed = crypto::seal(kKey, lugh::byte_span("x"), {}, random);
  auto other = kKey;
  other[0] ^= 1;
  EXPECT_FALSE(crypto::open(other, sealed.value, {}));
}

TEST(Aead, RefusesOtherAssociatedData) {
  FixedRandom random;
  const auto sealed = crypto::seal(kKey, lugh::byte_span("x"), lugh::byte_span("users/alice/3"), random);
  EXPECT_FALSE(crypto::open(kKey, sealed.value, lugh::byte_span("users/alice/4")));
  EXPECT_FALSE(crypto::open(kKey, sealed.value, {}));
}

TEST(Aead, RefusesEveryEditedByte) {
  FixedRandom random;
  const auto sealed = crypto::seal(kKey, lugh::byte_span("sixteen bytes!!!"), lugh::byte_span("ad"), random);
  for (std::size_t i = 0; i < sealed.value.size(); ++i) {
    auto edited = sealed.value;
    edited[i] ^= 0x80;
    EXPECT_FALSE(crypto::open(kKey, edited, lugh::byte_span("ad"))) << "byte " << i;
  }
}

TEST(Aead, RefusesTruncation) {
  FixedRandom random;
  const auto sealed = crypto::seal(kKey, lugh::byte_span("payload"), {}, random);
  for (std::size_t length = 0; length < sealed.value.size(); ++length) {
    EXPECT_FALSE(crypto::open(kKey, std::span(sealed.value).first(length), {})) << length;
  }
}

TEST(Aead, RefusesBadSizes) {
  FixedRandom random;
  EXPECT_FALSE(crypto::seal(lugh::Bytes(16, 0), lugh::byte_span("x"), {}, random).ok);
  EXPECT_FALSE(crypto::aes256gcm_encrypt(kKey, lugh::Bytes(8, 0), {}, {}).ok);
  EXPECT_FALSE(crypto::open(lugh::Bytes(31, 0), lugh::Bytes(40, 0), {}));
}

TEST(Aead, ABrokenRandomSourceSealsNothing) {
  FixedRandom random;
  random.fail = true;
  const auto sealed = crypto::seal(kKey, lugh::byte_span("x"), {}, random);
  EXPECT_FALSE(sealed.ok);
  EXPECT_TRUE(sealed.value.empty());
}

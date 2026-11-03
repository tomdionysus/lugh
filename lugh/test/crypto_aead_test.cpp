//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/crypto/aead.h"
#include "lugh/test/fixtures/hex.h"

namespace crypto = lugh::crypto;

namespace {

const lugh::Bytes kKey = from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

}  // namespace

// AES-256-GCM is Dannan's, tested there against the GCM specification. What is here is
// the sealed-value framing: the nonce in front, the tag behind.
TEST(Aead, SealThenOpen) {
  const auto plaintext = lugh::byte_span("a record");
  const auto associated = lugh::byte_span("users/alice/3");

  const auto sealed = crypto::seal(kKey, plaintext, associated);
  ASSERT_TRUE(sealed.ok) << sealed.error;
  EXPECT_EQ(sealed.value.size(), plaintext.size() + crypto::kAeadOverhead);

  const auto opened = crypto::open(kKey, sealed.value, associated);
  ASSERT_TRUE(opened);
  EXPECT_EQ(std::string(opened->begin(), opened->end()), "a record");
}

TEST(Aead, EachSealHasItsOwnNonce) {
  const auto first = crypto::seal(kKey, lugh::byte_span("same"), {});
  const auto second = crypto::seal(kKey, lugh::byte_span("same"), {});
  EXPECT_NE(first.value, second.value);
}

TEST(Aead, RefusesTheWrongKey) {
  const auto sealed = crypto::seal(kKey, lugh::byte_span("x"), {});
  auto other = kKey;
  other[0] ^= 1;
  EXPECT_FALSE(crypto::open(other, sealed.value, {}));
}

TEST(Aead, RefusesOtherAssociatedData) {
  const auto sealed = crypto::seal(kKey, lugh::byte_span("x"), lugh::byte_span("users/alice/3"));
  EXPECT_FALSE(crypto::open(kKey, sealed.value, lugh::byte_span("users/alice/4")));
  EXPECT_FALSE(crypto::open(kKey, sealed.value, {}));
}

TEST(Aead, RefusesEveryEditedByte) {
  const auto sealed = crypto::seal(kKey, lugh::byte_span("sixteen bytes!!!"), lugh::byte_span("ad"));
  for (std::size_t i = 0; i < sealed.value.size(); ++i) {
    auto edited = sealed.value;
    edited[i] ^= 0x80;
    EXPECT_FALSE(crypto::open(kKey, edited, lugh::byte_span("ad"))) << "byte " << i;
  }
}

TEST(Aead, RefusesTruncation) {
  const auto sealed = crypto::seal(kKey, lugh::byte_span("payload"), {});
  for (std::size_t length = 0; length < sealed.value.size(); ++length) {
    EXPECT_FALSE(crypto::open(kKey, std::span(sealed.value).first(length), {})) << length;
  }
}

TEST(Aead, RefusesBadSizes) {
  EXPECT_FALSE(crypto::seal(lugh::Bytes(16, 0), lugh::byte_span("x"), {}).ok);
  EXPECT_FALSE(crypto::open(lugh::Bytes(31, 0), lugh::Bytes(40, 0), {}));
}

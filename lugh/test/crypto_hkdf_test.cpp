//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/crypto/hkdf.h"
#include "lugh/test/fixtures/hex.h"

using lugh::crypto::hkdf_sha256;

// RFC 5869, appendix A.1.
TEST(Hkdf, Rfc5869Case1) {
  const auto out = hkdf_sha256(repeated(0x0b, 22), from_hex("000102030405060708090a0b0c"), from_hex("f0f1f2f3f4f5f6f7f8f9"), 42);
  ASSERT_TRUE(out.ok) << out.error;
  EXPECT_EQ(to_hex(out.value), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

// RFC 5869, appendix A.3: no salt and no info.
TEST(Hkdf, Rfc5869Case3) {
  const auto out = hkdf_sha256(repeated(0x0b, 22), {}, {}, 42);
  ASSERT_TRUE(out.ok) << out.error;
  EXPECT_EQ(to_hex(out.value), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

TEST(Hkdf, DifferentInfoDifferentKeys) {
  const auto key = repeated(0x42, 32);
  const auto a = hkdf_sha256(key, {}, lugh::byte_span("one use"), 32);
  const auto b = hkdf_sha256(key, {}, lugh::byte_span("another"), 32);
  EXPECT_NE(to_hex(a.value), to_hex(b.value));
}

TEST(Hkdf, RefusesWhatItCannotMake) {
  EXPECT_FALSE(hkdf_sha256({}, {}, {}, 32).ok);
  EXPECT_FALSE(hkdf_sha256(repeated(1, 32), {}, {}, 0).ok);
  EXPECT_FALSE(hkdf_sha256(repeated(1, 32), {}, {}, 255 * 32 + 1).ok);
  EXPECT_TRUE(hkdf_sha256(repeated(1, 32), {}, {}, 255 * 32).ok);
}

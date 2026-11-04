//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/core/encoding.h"
#include "lugh/test/fixtures/hex.h"

using lugh::byte_span;
using namespace lugh::encoding;

TEST(Encoding, Hex) {
  EXPECT_EQ(hex(from_hex("00ff10ab")), "00ff10ab");
  EXPECT_EQ(hex({}), "");
}

// RFC 4648, section 10, unpadded.
TEST(Encoding, Base32KnownAnswers) {
  EXPECT_EQ(base32(byte_span("")), "");
  EXPECT_EQ(base32(byte_span("f")), "MY");
  EXPECT_EQ(base32(byte_span("fo")), "MZXQ");
  EXPECT_EQ(base32(byte_span("foo")), "MZXW6");
  EXPECT_EQ(base32(byte_span("foob")), "MZXW6YQ");
  EXPECT_EQ(base32(byte_span("fooba")), "MZXW6YTB");
  EXPECT_EQ(base32(byte_span("foobar")), "MZXW6YTBOI");
}

TEST(Encoding, Base32DecodesEitherCase) {
  for (const auto* text : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
    const auto encoded = base32(byte_span(text));
    const auto decoded = base32_decode(encoded);
    ASSERT_TRUE(decoded) << text;
    EXPECT_EQ(std::string(decoded->begin(), decoded->end()), text);
  }
  const auto lower = base32_decode("mzxw6ytboi");
  ASSERT_TRUE(lower);
  EXPECT_EQ(std::string(lower->begin(), lower->end()), "foobar");
}

TEST(Encoding, Base32RefusesWhatIsNotExactly) {
  EXPECT_FALSE(base32_decode("MZXW6YTBOI="));
  EXPECT_FALSE(base32_decode("MZXW 6YTB"));
  EXPECT_FALSE(base32_decode("MZXW1"));
  // "MZ" is "f" with zero trailing bits; "M3" leaves bits set that no encoder would.
  EXPECT_TRUE(base32_decode("MY"));
  EXPECT_FALSE(base32_decode("MZ"));
  // A lone character carries five bits, not a byte.
  EXPECT_FALSE(base32_decode("M"));
}

// RFC 4648, section 10, in the URL-safe alphabet and unpadded.
TEST(Encoding, Base64UrlKnownAnswers) {
  EXPECT_EQ(base64url(byte_span("")), "");
  EXPECT_EQ(base64url(byte_span("f")), "Zg");
  EXPECT_EQ(base64url(byte_span("fo")), "Zm8");
  EXPECT_EQ(base64url(byte_span("foo")), "Zm9v");
  EXPECT_EQ(base64url(byte_span("foob")), "Zm9vYg");
  EXPECT_EQ(base64url(byte_span("fooba")), "Zm9vYmE");
  EXPECT_EQ(base64url(byte_span("foobar")), "Zm9vYmFy");
  EXPECT_EQ(base64url(from_hex("fbff")), "-_8");
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "authn/totp.h"

#include <gtest/gtest.h>

using lugh::byte_span;
using namespace lugh::authn;

namespace {

// The RFCs' shared secret: "12345678901234567890".
const auto kSecret = byte_span("12345678901234567890");

}  // namespace

// RFC 4226, appendix D.
TEST(Totp, HotpKnownAnswers) {
  const std::uint32_t expected[] = {755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489};
  for (std::uint64_t counter = 0; counter < 10; ++counter) EXPECT_EQ(hotp(kSecret, counter, 6), expected[counter]) << counter;
}

// RFC 6238, appendix B, the SHA-1 rows (eight digits there).
TEST(Totp, TotpKnownAnswers) {
  const std::pair<std::uint64_t, std::uint32_t> rows[] = {
      {59, 94287082}, {1111111109, 7081804}, {1111111111, 14050471}, {1234567890, 89005924}, {2000000000, 69279037}, {20000000000, 65353130},
  };
  for (const auto& [time, code] : rows) EXPECT_EQ(hotp(kSecret, totp_step(time), 8), code) << time;
}

TEST(Totp, SixDigitsZeroPadded) {
  // RFC 4226's counter 0, which has no leading zero, and a search for one that does.
  EXPECT_EQ(totp_code(kSecret, 0), "755224");
  for (std::uint64_t step = 0; step < 1000; ++step) {
    const auto code = totp_code(kSecret, step);
    ASSERT_EQ(code.size(), 6u);
    if (code[0] == '0') return;
  }
  FAIL() << "no code with a leading zero in 1000 steps";
}

TEST(Totp, OneStepEitherSide) {
  const std::uint64_t now = 1111111111;
  const auto step = totp_step(now);
  EXPECT_EQ(totp_match(kSecret, totp_code(kSecret, step), now, std::nullopt), step);
  EXPECT_EQ(totp_match(kSecret, totp_code(kSecret, step - 1), now, std::nullopt), step - 1);
  EXPECT_EQ(totp_match(kSecret, totp_code(kSecret, step + 1), now, std::nullopt), step + 1);
  EXPECT_FALSE(totp_match(kSecret, totp_code(kSecret, step - 2), now, std::nullopt));
  EXPECT_FALSE(totp_match(kSecret, totp_code(kSecret, step + 2), now, std::nullopt));
}

TEST(Totp, AUsedStepOrAnEarlierOneIsRefused) {
  const std::uint64_t now = 1111111111;
  const auto step = totp_step(now);
  const auto code = totp_code(kSecret, step);
  EXPECT_FALSE(totp_match(kSecret, code, now, step));
  EXPECT_FALSE(totp_match(kSecret, code, now, step + 1));
  EXPECT_FALSE(totp_match(kSecret, totp_code(kSecret, step - 1), now, step - 1));
  EXPECT_EQ(totp_match(kSecret, totp_code(kSecret, step + 1), now, step), step + 1);
}

TEST(Totp, OnlySixDigits) {
  const std::uint64_t now = 59;
  EXPECT_FALSE(totp_match(kSecret, "", now, std::nullopt));
  EXPECT_FALSE(totp_match(kSecret, "28708", now, std::nullopt));
  EXPECT_FALSE(totp_match(kSecret, "2870820", now, std::nullopt));
  EXPECT_FALSE(totp_match(kSecret, "28708a", now, std::nullopt));
  EXPECT_FALSE(totp_match(kSecret, " 287082", now, std::nullopt));
}

TEST(Totp, OtpauthUri) {
  const auto uri = otpauth_uri("Lugh", "alice smith", kSecret);
  EXPECT_EQ(uri.reveal(), "otpauth://totp/Lugh:alice%20smith?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Lugh&algorithm=SHA1&digits=6&period=30");
}

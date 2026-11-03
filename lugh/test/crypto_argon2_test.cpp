//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/crypto/argon2.h"
#include "lugh/test/fixtures/hex.h"

using lugh::crypto::argon2id;
using lugh::crypto::Argon2Params;

namespace {

// Cheap enough for a test, valid all the same.
const Argon2Params kCheap{64, 1, 1};

}  // namespace

// RFC 9106, section 5.3: Argon2id with a secret and associated data.
TEST(Argon2, Rfc9106Vector) {
  const auto out = argon2id(Argon2Params{32, 3, 4}, repeated(0x01, 32), repeated(0x02, 16), 32, repeated(0x03, 8), repeated(0x04, 12));
  ASSERT_TRUE(out.ok) << out.error;
  EXPECT_EQ(to_hex(out.value), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

TEST(Argon2, SameInputSameOutput) {
  const auto a = argon2id(kCheap, lugh::byte_span("password"), lugh::byte_span("saltsaltsalt"), 32);
  const auto b = argon2id(kCheap, lugh::byte_span("password"), lugh::byte_span("saltsaltsalt"), 32);
  ASSERT_TRUE(a.ok) << a.error;
  EXPECT_EQ(to_hex(a.value), to_hex(b.value));
}

TEST(Argon2, EveryInputMatters) {
  const auto base = to_hex(argon2id(kCheap, lugh::byte_span("password"), lugh::byte_span("saltsaltsalt"), 32).value);
  EXPECT_NE(base, to_hex(argon2id(kCheap, lugh::byte_span("passwore"), lugh::byte_span("saltsaltsalt"), 32).value));
  EXPECT_NE(base, to_hex(argon2id(kCheap, lugh::byte_span("password"), lugh::byte_span("saltsaltsalu"), 32).value));
  EXPECT_NE(base, to_hex(argon2id(Argon2Params{64, 2, 1}, lugh::byte_span("password"), lugh::byte_span("saltsaltsalt"), 32).value));
  EXPECT_NE(base, to_hex(argon2id(Argon2Params{128, 1, 1}, lugh::byte_span("password"), lugh::byte_span("saltsaltsalt"), 32).value));
  EXPECT_NE(base, to_hex(argon2id(kCheap, lugh::byte_span("password"), lugh::byte_span("saltsaltsalt"), 32, lugh::byte_span("pepper")).value));
}

TEST(Argon2, TheDefaultsAreRfc9106sSecondRecommendation) {
  const Argon2Params defaults;
  EXPECT_EQ(defaults.memory_kib, 64u * 1024);
  EXPECT_EQ(defaults.iterations, 3u);
  EXPECT_EQ(defaults.lanes, 4u);
  EXPECT_TRUE(defaults.valid());
}

TEST(Argon2, RefusesCostsOutOfRange) {
  const auto salt = lugh::byte_span("saltsaltsalt");
  EXPECT_FALSE(argon2id(Argon2Params{7, 1, 1}, {}, salt, 32).ok);
  EXPECT_FALSE(argon2id(Argon2Params{64, 0, 1}, {}, salt, 32).ok);
  EXPECT_FALSE(argon2id(Argon2Params{64, 1, 0}, {}, salt, 32).ok);
  EXPECT_FALSE(argon2id(Argon2Params{64, 1, 9}, {}, salt, 32).ok);  // under 8 KiB a lane
  EXPECT_FALSE(argon2id(Argon2Params{Argon2Params::kMostMemoryKib + 1, 1, 1}, {}, salt, 32).ok);
  EXPECT_FALSE(argon2id(Argon2Params{64, Argon2Params::kMostIterations + 1, 1}, {}, salt, 32).ok);
}

TEST(Argon2, RefusesAShortSaltAndOddLengths) {
  EXPECT_FALSE(argon2id(kCheap, lugh::byte_span("pw"), lugh::byte_span("short"), 32).ok);
  EXPECT_FALSE(argon2id(kCheap, lugh::byte_span("pw"), lugh::byte_span("saltsalt"), 3).ok);
  EXPECT_TRUE(argon2id(kCheap, lugh::byte_span("pw"), lugh::byte_span("saltsalt"), 4).ok);
}

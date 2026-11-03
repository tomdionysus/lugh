//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/crypto/argon2.h"

// Argon2id itself is Dannan's, tested there against RFC 9106. What Lugh adds is the ceiling
// on costs read from a record, and the stretch into its secure buffer.
using lugh::crypto::Argon2Costs;
using lugh::crypto::bounded;

TEST(Argon2, TheDefaultsAreWithinTheCeiling) { EXPECT_TRUE(bounded(Argon2Costs{})); }

TEST(Argon2, CostsOutsideTheCeilingAreRefusedBeforeAnythingIsSpent) {
  EXPECT_FALSE(bounded(Argon2Costs{lugh::crypto::kArgon2MostMemoryKib + 1, 3, 4}));
  EXPECT_FALSE(bounded(Argon2Costs{64 * 1024, lugh::crypto::kArgon2MostIterations + 1, 4}));
  EXPECT_FALSE(bounded(Argon2Costs{64 * 1024, 3, lugh::crypto::kArgon2MostLanes + 1}));
  EXPECT_FALSE(bounded(Argon2Costs{64 * 1024, 0, 4}));
  EXPECT_FALSE(bounded(Argon2Costs{64 * 1024, 3, 0}));
  // Argon2 needs 8 KiB a lane.
  EXPECT_FALSE(bounded(Argon2Costs{31, 1, 4}));
  EXPECT_TRUE(bounded(Argon2Costs{32, 1, 4}));
}

TEST(Argon2, StretchIsArgon2id) {
  const auto salt = std::vector<unsigned char>(16, 0x02);
  const auto password = lugh::byte_span("correct horse battery");
  const auto one = lugh::crypto::stretch(password, salt, Argon2Costs{64, 1, 1}, 32);
  const auto two = lugh::crypto::stretch(password, salt, Argon2Costs{64, 1, 1}, 32);
  ASSERT_TRUE(one.ok) << one.error;
  EXPECT_EQ(one.value.size(), 32u);
  EXPECT_EQ(one.value, two.value);
  EXPECT_FALSE(lugh::crypto::stretch(password, std::vector<unsigned char>(4, 0), Argon2Costs{64, 1, 1}, 32).ok);
}

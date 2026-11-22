//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// Every Lugh fuzz target (lugh/fuzz/), on every gate and in CI, through Dannan's harness: its seeds,
// then thousands of mutations of them and random inputs. A target that crashes, or finds what it
// says must not happen, fails here. Deterministic: the same inputs every run, so a failure
// reproduces. Campaigns still run the libFuzzer binaries for longer.

#include <gtest/gtest.h>

#include <set>
#include <string>

#include "dannan/fuzz/fuzz.h"

TEST(FuzzSmoke, EveryTargetIsRegisteredOnce) {
  const std::set<std::string> expected{"api_request", "ber",     "client",  "dn",        "envelope", "filter",  "form",
                                       "jws",         "keyring", "records", "store_log", "scope",    "webauthn"};
  std::set<std::string> registered;
  for (const auto& target : dannan::fuzz::targets()) EXPECT_TRUE(registered.insert(target.name).second) << target.name << " twice";
  EXPECT_EQ(registered, expected);
}

// A target without seeds is refused by smoke(); a corpus directory moved or emptied shows here.
TEST(FuzzSmoke, EveryTargetHasSeeds) {
  for (const auto& target : dannan::fuzz::targets()) EXPECT_FALSE(target.seeds().empty()) << target.name;
}

TEST(FuzzSmoke, EveryTargetSurvivesMutatedAndRandomInputs) {
  for (const auto& target : dannan::fuzz::targets()) {
    SCOPED_TRACE(target.name);
    EXPECT_NO_THROW(EXPECT_GT(dannan::fuzz::smoke(target), 3500u));
  }
}

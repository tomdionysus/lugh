//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/backoff.h"

using lugh::authn::Backoff;
using namespace std::chrono_literals;

namespace {

const Backoff::TimePoint kStart{std::chrono::hours(1)};

}  // namespace

TEST(Backoff, FreeFailuresThenDoublingWaits) {
  Backoff backoff(Backoff::Rules{});
  auto now = kStart;
  for (int i = 0; i < 4; ++i) {
    backoff.failed("a", now);
    EXPECT_FALSE(backoff.wait("a", now)) << i;
  }
  backoff.failed("a", now);
  EXPECT_EQ(backoff.wait("a", now), 1s);
  backoff.failed("a", now);
  EXPECT_EQ(backoff.wait("a", now), 2s);
  backoff.failed("a", now);
  EXPECT_EQ(backoff.wait("a", now), 4s);

  now += 3s;
  EXPECT_EQ(backoff.wait("a", now), 1s);
  now += 1s;
  EXPECT_FALSE(backoff.wait("a", now));
}

TEST(Backoff, TheWaitHasACeiling) {
  Backoff backoff(Backoff::Rules{});
  for (int i = 0; i < 100; ++i) backoff.failed("a", kStart);
  EXPECT_EQ(backoff.wait("a", kStart), std::chrono::seconds(15min));
}

TEST(Backoff, KeysAreSeparateAndSuccessClearsOne) {
  Backoff backoff(Backoff::Rules{});
  for (int i = 0; i < 6; ++i) {
    backoff.failed("a", kStart);
    backoff.failed("b", kStart);
  }
  backoff.succeeded("a");
  EXPECT_FALSE(backoff.wait("a", kStart));
  EXPECT_TRUE(backoff.wait("b", kStart));
}

TEST(Backoff, QuietKeysAreForgotten) {
  Backoff backoff(Backoff::Rules{});
  for (int i = 0; i < 20; ++i) backoff.failed("a", kStart);
  EXPECT_FALSE(backoff.wait("a", kStart + 1h));
  // And start again from nothing.
  backoff.failed("a", kStart + 1h);
  EXPECT_FALSE(backoff.wait("a", kStart + 1h));
}

TEST(Backoff, MadeUpKeysDoNotGrowWithoutBound) {
  Backoff backoff(Backoff::Rules{}, 100);
  for (int i = 0; i < 150; ++i) backoff.failed("old" + std::to_string(i), kStart);
  for (int i = 0; i < 150; ++i) backoff.failed("new" + std::to_string(i), kStart + 2h);
  EXPECT_LE(backoff.size(), 152u);
}

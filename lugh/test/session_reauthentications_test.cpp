//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The re-authentication window (TODO/2026-11-15-self-factors.md, the maintainer 2026-11-15): ten minutes from
// a factor proved, per session, on stepped time; bounded, and failing closed when full.

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/session/reauthentications.h"

using lugh::session::Reauthentications;

TEST(Reauthentications, TenMinutesFromAFactorProved) {
  dannan::test::SteppedTime time;
  Reauthentications windows(time);
  EXPECT_EQ(windows.window(), std::chrono::minutes(10));
  EXPECT_FALSE(windows.open_now("s1")) << "closed until a factor is proved";

  windows.open("s1");
  EXPECT_TRUE(windows.open_now("s1"));
  EXPECT_FALSE(windows.open_now("s2")) << "one session's window is not another's";
  time.advance(std::chrono::minutes(10) - std::chrono::milliseconds(1));
  EXPECT_TRUE(windows.open_now("s1"));
  time.advance(std::chrono::milliseconds(1));
  EXPECT_FALSE(windows.open_now("s1")) << "closed at ten minutes";
}

TEST(Reauthentications, ProvingAgainStartsTheWindowAgain) {
  dannan::test::SteppedTime time;
  Reauthentications windows(time);
  windows.open("s1");
  time.advance(std::chrono::minutes(8));
  const auto until = windows.open("s1");
  EXPECT_EQ(until, time.now() + std::chrono::minutes(10));
  time.advance(std::chrono::minutes(9));
  EXPECT_TRUE(windows.open_now("s1"));
}

TEST(Reauthentications, WhenFullTheWindowClosingSoonestGoes) {
  dannan::test::SteppedTime time;
  Reauthentications windows(time, std::chrono::minutes(10), 2);
  windows.open("s1");
  time.advance(std::chrono::minutes(1));
  windows.open("s2");
  time.advance(std::chrono::minutes(1));
  windows.open("s3");
  EXPECT_FALSE(windows.open_now("s1")) << "closed early, which fails closed";
  EXPECT_TRUE(windows.open_now("s2"));
  EXPECT_TRUE(windows.open_now("s3"));

  // A closed window makes room before an open one is dropped.
  time.advance(std::chrono::minutes(9));
  windows.open("s4");
  EXPECT_FALSE(windows.open_now("s2"));
  EXPECT_TRUE(windows.open_now("s3"));
  EXPECT_TRUE(windows.open_now("s4"));
}

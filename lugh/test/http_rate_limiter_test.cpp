//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/http/rate_limiter.h"

using lugh::http::RateLimiter;
using lugh::http::Throttle;
using TimePoint = dannan::contract::TimePoint;
using namespace std::chrono_literals;

TEST(RateLimiter, AllowsTheBurstThenRefuses) {
  RateLimiter limiter;
  const RateLimiter::Policy policy{3, 60};
  const auto now = TimePoint{};

  EXPECT_FALSE(limiter.take("k", policy, now));
  EXPECT_FALSE(limiter.take("k", policy, now));
  EXPECT_FALSE(limiter.take("k", policy, now));

  const auto wait = limiter.take("k", policy, now);
  ASSERT_TRUE(wait);
  EXPECT_EQ(*wait, 1s);
}

TEST(RateLimiter, RefillsAtTheRate) {
  RateLimiter limiter;
  const RateLimiter::Policy policy{1, 6};  // one every ten seconds
  const auto start = TimePoint{};

  EXPECT_FALSE(limiter.take("k", policy, start));
  EXPECT_EQ(*limiter.take("k", policy, start), 10s);
  EXPECT_TRUE(limiter.take("k", policy, start + 9s));
  EXPECT_FALSE(limiter.take("k", policy, start + 20s));
}

TEST(RateLimiter, KeysAreIndependent) {
  RateLimiter limiter;
  const RateLimiter::Policy policy{1, 1};

  EXPECT_FALSE(limiter.take("a", policy, {}));
  EXPECT_FALSE(limiter.take("b", policy, {}));
  EXPECT_TRUE(limiter.take("a", policy, {}));
}

TEST(RateLimiter, ZeroIsUnlimited) {
  RateLimiter limiter;
  for (int i = 0; i < 1000; ++i) EXPECT_FALSE(limiter.take("k", RateLimiter::Policy{0, 0}, {}));
  EXPECT_EQ(limiter.size(), 0u);
}

TEST(RateLimiter, NeverHoldsMoreThanItsBound) {
  // Callers choose the keys, so a stream of made-up names (accounts, addresses) must not grow it.
  RateLimiter limiter(4);
  const RateLimiter::Policy policy{1, 60};
  for (int i = 0; i < 50; ++i) {
    limiter.take("k" + std::to_string(i), policy, TimePoint{} + std::chrono::seconds(i % 3));
    EXPECT_LE(limiter.size(), 4u);
  }
  // A key just taken is still held, and still limited.
  EXPECT_TRUE(limiter.take("k49", policy, TimePoint{} + 1s));
}

TEST(Throttle, ReadsTheInjectedClock) {
  dannan::test::SteppedTime time;
  Throttle throttle(time);
  const RateLimiter::Policy policy{1, 6};

  EXPECT_FALSE(throttle.take("k", policy));
  EXPECT_TRUE(throttle.take("k", policy));

  time.advance(10s);
  EXPECT_FALSE(throttle.take("k", policy));
}

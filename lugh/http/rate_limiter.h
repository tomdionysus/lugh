//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <optional>
#include <string>

#include "dannan/contract/time_source.h"
#include "dannan/listen/rate_limiter.h"

namespace lugh::http {

// Token buckets keyed by what the caller is limited as (a client address, a session, an
// account): Dannan's since 0.12.0, moved there from here. A key gets `burst` requests at once,
// then `per_minute` a minute; a refusal says how long to wait, for Retry-After. Held in memory, so
// limiting needs no store round trip, and bounded in its keys, since callers choose them.
using RateLimiter = dannan::listen::RateLimiter;

// The limits for each kind of caller. Sign-in limits join these with the sign-in pages.
struct RateLimits {
  // Open routes, and requests whose credential did not resolve, per client address.
  RateLimiter::Policy open{30, 30};
  // A resolved caller, per caller: room for the dashboard's bursts and a script's loops.
  RateLimiter::Policy caller{120, 600};
};

// The limiter, the limits and the clock, shared by the router and by routes that limit
// further.
class Throttle {
 public:
  explicit Throttle(const dannan::contract::TimeSource& time, RateLimits limits = {}) : _time(time), _limits(limits) {}

  const RateLimits& limits() const { return _limits; }

  std::optional<std::chrono::seconds> take(const std::string& key, const RateLimiter::Policy& policy) { return _limiter.take(key, policy, _time.now()); }

 private:
  const dannan::contract::TimeSource& _time;
  RateLimits _limits;
  RateLimiter _limiter;
};

}  // namespace lugh::http

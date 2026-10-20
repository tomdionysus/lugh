#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

#include "system/clock.h"

namespace lugh::http {

// Token buckets keyed by what the caller is limited as: a client address, a session, an
// account. A key gets `burst` requests at once and then `per_minute` a minute; a refusal
// says how long to wait, for Retry-After. Held in memory, so limiting needs no store round
// trip.
class RateLimiter {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;

  struct Policy {
    std::uint32_t burst = 0;
    std::uint32_t per_minute = 0;

    // Zero in either means no limit.
    bool unlimited() const { return burst == 0 || per_minute == 0; }
  };

  // Above this many keys, full buckets are dropped. Callers choose the keys, so without a
  // bound a stream of made-up account names would grow the map without limit.
  explicit RateLimiter(std::size_t prune_above = 10000) : _prune_above(prune_above) {}

  // Takes one request from `key`'s bucket. Returns nothing when it is allowed, otherwise
  // the wait until it would be, rounded up to at least one second.
  std::optional<std::chrono::seconds> take(const std::string& key, const Policy& policy, TimePoint now) {
    if (policy.unlimited()) return std::nullopt;

    std::lock_guard<std::mutex> lock(_mutex);

    if (_buckets.size() > _prune_above) _prune(now);

    auto [it, made] = _buckets.try_emplace(key, Bucket{static_cast<double>(policy.burst), now, policy});
    auto& bucket = it->second;

    if (!made) _refill(bucket, now);

    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      return std::nullopt;
    }

    const auto seconds_per_token = 60.0 / policy.per_minute;
    const auto wait = std::ceil((1.0 - bucket.tokens) * seconds_per_token);

    return std::chrono::seconds(std::max<std::int64_t>(1, static_cast<std::int64_t>(wait)));
  }

  std::size_t size() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _buckets.size();
  }

 private:
  struct Bucket {
    double tokens;
    TimePoint at;
    Policy policy;
  };

  static void _refill(Bucket& bucket, TimePoint now) {
    if (now <= bucket.at) return;

    const auto elapsed = std::chrono::duration<double>(now - bucket.at).count();
    bucket.tokens = std::min<double>(bucket.policy.burst, bucket.tokens + elapsed * bucket.policy.per_minute / 60.0);
    bucket.at = now;
  }

  void _prune(TimePoint now) {
    for (auto it = _buckets.begin(); it != _buckets.end();) {
      _refill(it->second, now);
      it = it->second.tokens >= it->second.policy.burst ? _buckets.erase(it) : std::next(it);
    }
  }

  mutable std::mutex _mutex;
  std::size_t _prune_above;
  std::unordered_map<std::string, Bucket> _buckets;
};

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
  explicit Throttle(std::shared_ptr<system::Clock> clock, RateLimits limits = {}) : _clock(std::move(clock)), _limits(limits) {}

  const RateLimits& limits() const { return _limits; }

  std::optional<std::chrono::seconds> take(const std::string& key, const RateLimiter::Policy& policy) {
    return _limiter.take(key, policy, _clock->steady_now());
  }

 private:
  std::shared_ptr<system::Clock> _clock;
  RateLimits _limits;
  RateLimiter _limiter;
};

}  // namespace lugh::http

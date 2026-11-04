//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "dannan/contract/thread_safety.h"

namespace lugh::authn {

// Failed sign-ins, per account and per source address, answered with a growing wait rather
// than a lock, so that someone who knows a user's name cannot lock them out on purpose: the
// most they can do is make each guess slower, theirs included. Held in memory, per node;
// P8 sums it across the cluster by gossip, so a partition loosens it, never removes it.
class Backoff {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;

  struct Rules {
    // Failures before any wait.
    std::uint32_t free_failures = 5;
    // The first wait, doubled at each failure after it, up to `longest`.
    std::chrono::seconds first{1};
    std::chrono::seconds longest{std::chrono::minutes(15)};
    // A key with no failure for this long starts again.
    std::chrono::seconds forget_after{std::chrono::hours(1)};
  };

  // Above this many keys, forgotten ones are dropped: callers choose the keys, and a stream
  // of made-up names must not grow the map without bound.
  explicit Backoff(Rules rules, std::size_t prune_above = 100000) : _rules(rules), _prune_above(prune_above) {}

  // How long until `key` may try again; nothing when it may now.
  std::optional<std::chrono::seconds> wait(const std::string& key, TimePoint now) const {
    dannan::contract::Lock lock(_mutex);
    const auto found = _keys.find(key);
    if (found == _keys.end() || _forgotten(found->second, now)) return std::nullopt;
    const auto until = found->second.last + _delay(found->second.failures);
    if (now >= until) return std::nullopt;
    return std::max(std::chrono::seconds(1), std::chrono::ceil<std::chrono::seconds>(until - now));
  }

  void failed(const std::string& key, TimePoint now) {
    dannan::contract::Lock lock(_mutex);
    if (_keys.size() > _prune_above) _prune(now);
    auto& state = _keys[key];
    if (_forgotten(state, now)) state.failures = 0;
    ++state.failures;
    state.last = now;
  }

  void succeeded(const std::string& key) {
    dannan::contract::Lock lock(_mutex);
    _keys.erase(key);
  }

  std::size_t size() const {
    dannan::contract::Lock lock(_mutex);
    return _keys.size();
  }

 private:
  struct State {
    std::uint32_t failures = 0;
    TimePoint last{};
  };

  bool _forgotten(const State& state, TimePoint now) const { return state.failures == 0 || now - state.last >= _rules.forget_after; }

  std::chrono::seconds _delay(std::uint32_t failures) const {
    if (failures < _rules.free_failures) return std::chrono::seconds(0);
    auto delay = _rules.first;
    for (std::uint32_t i = _rules.free_failures; i < failures && delay < _rules.longest; ++i) delay *= 2;
    return std::min(delay, _rules.longest);
  }

  void _prune(TimePoint now) DANNAN_REQUIRES(_mutex) {
    for (auto it = _keys.begin(); it != _keys.end();) it = _forgotten(it->second, now) ? _keys.erase(it) : std::next(it);
  }

  Rules _rules;
  std::size_t _prune_above;
  mutable dannan::contract::Mutex _mutex;
  std::unordered_map<std::string, State> _keys DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::authn

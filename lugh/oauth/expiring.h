//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/core/secure_bytes.h"

namespace lugh::oauth {

// What lives for seconds or minutes and is used once: an authorisation code, a pushed
// request's URI, an authorisation request waiting on a sign-in. Held in memory on the node
// that made it, under the SHA-256 of a random handle, so memory holds nothing that works as
// the handle: the single-use rule (TODO/2026-11-04-oauth.md, "Grants") for things a restart
// may lose, since losing one costs a user a click. take() removes as it reads, so of two
// redemptions racing, one wins. Past `most`, the oldest goes. Safe from any number of threads.
template <typename T>
class Expiring {
 public:
  Expiring(const dannan::contract::TimeSource& time, std::chrono::seconds lifetime, std::size_t most = 10000) : _time(time), _lifetime(lifetime), _most(most) {}

  // `value` under a new handle, which is answered: 256 random bits, base64url.
  std::string put(T value) {
    auto handle = encoding::base64url(secure_random(32));
    const auto now = _time.now();
    dannan::contract::Lock state(_mutex);
    std::erase_if(_held, [&](const auto& one) { return now - one.second.made > _lifetime; });
    if (_held.size() >= _most) {
      _held.erase(std::min_element(_held.begin(), _held.end(), [](const auto& a, const auto& b) { return a.second.made < b.second.made; }));
    }
    _held.emplace(key_of(handle), Held{std::move(value), now});
    return handle;
  }

  // `value` under a handle the caller chose (a client assertion's jti): false, changing
  // nothing, when one is already held under it.
  bool put_as(std::string_view handle, T value) {
    const auto now = _time.now();
    const auto key = key_of(handle);
    dannan::contract::Lock state(_mutex);
    std::erase_if(_held, [&](const auto& one) { return now - one.second.made > _lifetime; });
    if (_held.count(key)) return false;
    if (_held.size() >= _most) {
      _held.erase(std::min_element(_held.begin(), _held.end(), [](const auto& a, const auto& b) { return a.second.made < b.second.made; }));
    }
    _held.emplace(key, Held{std::move(value), now});
    return true;
  }

  // The value, removed: nothing for a handle unknown, used, or expired.
  std::optional<T> take(std::string_view handle) {
    const auto now = _time.now();
    dannan::contract::Lock state(_mutex);
    const auto found = _held.find(key_of(handle));
    if (found == _held.end()) return std::nullopt;
    auto held = std::move(found->second);
    _held.erase(found);
    if (now - held.made > _lifetime) return std::nullopt;
    return std::move(held.value);
  }

  // The value, left in place.
  std::optional<T> peek(std::string_view handle) const {
    const auto now = _time.now();
    dannan::contract::Lock state(_mutex);
    const auto found = _held.find(key_of(handle));
    if (found == _held.end() || now - found->second.made > _lifetime) return std::nullopt;
    return found->second.value;
  }

  std::chrono::seconds lifetime() const { return _lifetime; }

 private:
  struct Held {
    T value;
    dannan::contract::TimePoint made;
  };

  static std::string key_of(std::string_view handle) {
    return dannan::identity::hex(dannan::identity::sha256({reinterpret_cast<const unsigned char*>(handle.data()), handle.size()}));
  }

  const dannan::contract::TimeSource& _time;
  std::chrono::seconds _lifetime;
  std::size_t _most;
  mutable dannan::contract::Mutex _mutex;
  std::map<std::string, Held> _held DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::oauth

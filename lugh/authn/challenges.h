//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/core/secure_bytes.h"

namespace lugh::authn {

// WebAuthn challenges (TODO/2026-11-15-p11-webauthn.md, W4). A passwordless sign-in needs a
// challenge before anyone is known, and Lugh holds nothing for an anonymous visitor (session/
// pre_sessions.h), so issuing holds nothing either: a challenge is 16 random bytes, its expiry
// and a MAC under this process's own key over both and a binding (the visitor's sign-in cookie),
// so it is good only for the visitor it was issued to, only here, and only until it expires.
//
// Single use: claim() takes a challenge, refusing one that is forged, expired, bound to another
// visitor or already claimed; release() gives back one whose ceremony then failed. So two
// submissions of one assertion cannot both pass, and only the ceremonies that succeeded stay
// in the used set until they expire. The set is bounded: past `most`, expired entries go first,
// then a claim is refused, which fails closed. Not oauth::Expiring, which drops its oldest when
// full: right for a code whose loss costs a click, wrong for a claim whose loss allows a replay.
// Safe from any number of threads.
class Challenges {
 public:
  static constexpr std::size_t kBytes = 40;

  Challenges(const dannan::contract::TimeSource& time, std::chrono::seconds lifetime = std::chrono::minutes(5), std::size_t most = 10000);

  // A new challenge's bytes, for the ceremony's options.
  std::string issue(std::string_view binding) const;

  bool claim(std::string_view challenge, std::string_view binding);
  void release(std::string_view challenge);

 private:
  std::string _mac(std::string_view body, std::string_view binding) const;

  const dannan::contract::TimeSource& _time;
  std::chrono::seconds _lifetime;
  std::size_t _most;
  SecureBuffer _key;

  mutable dannan::contract::Mutex _mutex;
  // A claimed challenge and when it expires.
  std::map<std::string, dannan::contract::TimePoint, std::less<>> _used DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::authn

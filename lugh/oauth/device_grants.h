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
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/oauth/issuer.h"

namespace lugh::oauth {

// The device authorisation grant (RFC 8628): a device that cannot show a browser asks for a
// code, its user approves it on another device at /signin/device, and the device polls the
// token endpoint until it has its tokens. Each grant lives ten minutes in memory on the node
// that made it, single use like an authorisation code (TODO/2026-11-04-oauth.md, "Grants").
// Safe from any number of threads.
class DeviceGrants {
 public:
  static constexpr std::chrono::seconds kLifetime{600};
  static constexpr std::chrono::seconds kInterval{5};
  // RFC 8628 section 6.1: no vowels, so a code spells nothing; 20^8 codes.
  static constexpr std::string_view kAlphabet = "BCDFGHJKLMNPQRSTVWXZ";
  static constexpr std::size_t kUserCodeLength = 8;

  struct Started {
    std::string device_code;
    // As shown: "XXXX-XXXX".
    std::string user_code;
  };

  // A request waiting on its user, as the approval page shows it.
  struct Waiting {
    std::string client_id;
    std::vector<std::string> scopes;
  };

  enum class Poll { pending, slow_down, denied, expired, approved, unknown };

  struct Polled {
    Poll state = Poll::unknown;
    // When approved: the person's grant, to issue tokens from.
    std::optional<CodeGrant> grant;
  };

  DeviceGrants(const dannan::contract::TimeSource& time, std::size_t most = 10000);

  Started start(std::string client_id, std::vector<std::string> scopes);

  // The user code typed, any case, with or without its dash: the request it names, if live and
  // not yet answered.
  std::optional<Waiting> find(std::string_view user_code) const;

  // The person's answer. False when the code names nothing live and unanswered.
  bool approve(std::string_view user_code, CodeGrant grant);
  bool deny(std::string_view user_code);

  // The device's poll for `device_code`, as `client_id`. An approved grant is answered once and
  // gone; polling faster than the interval is slow_down, and the interval grows by five seconds.
  Polled poll(std::string_view device_code, std::string_view client_id);

  // A user code as stored: upper case, without its dash; nothing for one that cannot be.
  static std::optional<std::string> normal(std::string_view user_code);

 private:
  struct Held {
    std::string client_id;
    std::vector<std::string> scopes;
    std::string user_code;
    dannan::contract::TimePoint made;
    std::optional<dannan::contract::TimePoint> polled;
    std::chrono::seconds interval = kInterval;
    bool denied = false;
    std::optional<CodeGrant> grant;
  };

  const dannan::contract::TimeSource& _time;
  std::size_t _most;
  mutable dannan::contract::Mutex _mutex;
  // By the SHA-256 of the device code; the user code finds its key.
  std::map<std::string, Held> _held DANNAN_GUARDED_BY(_mutex);
  std::map<std::string, std::string> _by_user_code DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::oauth

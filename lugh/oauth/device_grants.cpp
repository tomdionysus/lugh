//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/device_grants.h"

#include <algorithm>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"

namespace lugh::oauth {

namespace {

std::string key_of(std::string_view device_code) { return dannan::identity::hex(dannan::identity::sha256(byte_span(device_code))); }

}  // namespace

DeviceGrants::DeviceGrants(const dannan::contract::TimeSource& time, std::size_t most) : _time(time), _most(most) {}

std::optional<std::string> DeviceGrants::normal(std::string_view user_code) {
  std::string out;
  for (const char c : user_code) {
    if (c == '-' || c == ' ') continue;
    const char upper = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
    if (kAlphabet.find(upper) == std::string_view::npos) return std::nullopt;
    out.push_back(upper);
  }
  if (out.size() != kUserCodeLength) return std::nullopt;
  return out;
}

DeviceGrants::Started DeviceGrants::start(std::string client_id, std::vector<std::string> scopes) {
  const auto device_code = encoding::base64url(secure_random(32));
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  for (auto it = _held.begin(); it != _held.end();) {
    if (now - it->second.made > kLifetime) {
      _by_user_code.erase(it->second.user_code);
      it = _held.erase(it);
    } else {
      ++it;
    }
  }
  if (_held.size() >= _most) {
    const auto oldest = std::min_element(_held.begin(), _held.end(), [](const auto& a, const auto& b) { return a.second.made < b.second.made; });
    _by_user_code.erase(oldest->second.user_code);
    _held.erase(oldest);
  }
  // A user code no live grant has: 20^8 of them, so a clash is rare and simply drawn again.
  std::string user_code;
  do {
    user_code.clear();
    while (user_code.size() < kUserCodeLength) {
      // Only bytes below 240, a multiple of 20, so every letter is as likely as the next.
      for (const auto byte : secure_random(kUserCodeLength)) {
        if (byte < 240 && user_code.size() < kUserCodeLength) user_code.push_back(kAlphabet[byte % kAlphabet.size()]);
      }
    }
  } while (_by_user_code.count(user_code));
  const auto key = key_of(device_code);
  _held.emplace(key, Held{std::move(client_id), std::move(scopes), user_code, now, std::nullopt, kInterval, false, std::nullopt});
  _by_user_code.emplace(user_code, key);
  return Started{device_code, user_code.substr(0, 4) + "-" + user_code.substr(4)};
}

std::optional<DeviceGrants::Waiting> DeviceGrants::find(std::string_view user_code) const {
  const auto code = normal(user_code);
  if (!code) return std::nullopt;
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  const auto key = _by_user_code.find(*code);
  if (key == _by_user_code.end()) return std::nullopt;
  const auto& held = _held.at(key->second);
  if (now - held.made > kLifetime || held.denied || held.grant) return std::nullopt;
  return Waiting{held.client_id, held.scopes};
}

bool DeviceGrants::approve(std::string_view user_code, CodeGrant grant) {
  const auto code = normal(user_code);
  if (!code) return false;
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  const auto key = _by_user_code.find(*code);
  if (key == _by_user_code.end()) return false;
  auto& held = _held.at(key->second);
  if (now - held.made > kLifetime || held.denied || held.grant) return false;
  grant.client_id = held.client_id;
  grant.scopes = held.scopes;
  held.grant = std::move(grant);
  return true;
}

bool DeviceGrants::deny(std::string_view user_code) {
  const auto code = normal(user_code);
  if (!code) return false;
  dannan::contract::Lock state(_mutex);
  const auto key = _by_user_code.find(*code);
  if (key == _by_user_code.end()) return false;
  auto& held = _held.at(key->second);
  if (held.denied || held.grant) return false;
  held.denied = true;
  return true;
}

DeviceGrants::Polled DeviceGrants::poll(std::string_view device_code, std::string_view client_id) {
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  const auto found = _held.find(key_of(device_code));
  if (found == _held.end() || found->second.client_id != client_id) return {Poll::unknown, std::nullopt};
  auto& held = found->second;
  if (now - held.made > kLifetime) {
    _by_user_code.erase(held.user_code);
    _held.erase(found);
    return {Poll::expired, std::nullopt};
  }
  if (held.grant) {
    Polled out{Poll::approved, std::move(held.grant)};
    _by_user_code.erase(held.user_code);
    _held.erase(found);
    return out;
  }
  if (held.denied) {
    _by_user_code.erase(held.user_code);
    _held.erase(found);
    return {Poll::denied, std::nullopt};
  }
  // RFC 8628 section 3.5: too soon is slow_down, and the interval grows by five seconds.
  const bool too_soon = held.polled && now - *held.polled < held.interval;
  held.polled = now;
  if (too_soon) {
    held.interval += std::chrono::seconds(5);
    return {Poll::slow_down, std::nullopt};
  }
  return {Poll::pending, std::nullopt};
}

}  // namespace lugh::oauth

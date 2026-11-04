//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/session/pre_sessions.h"

#include <algorithm>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"

namespace lugh::session {

namespace {

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

// The map's key: the handle's hash, so memory holds nothing that works as the cookie.
std::string key_of(std::string_view handle) { return dannan::identity::hex(dannan::identity::sha256(bytes_of(handle))); }

}  // namespace

PreSessions::PreSessions(const dannan::contract::TimeSource& time, std::chrono::seconds lifetime, std::size_t most)
    : _time(time), _lifetime(lifetime), _most(most), _key(secure_random(32)) {}

std::string PreSessions::new_handle() { return encoding::base64url(secure_random(kHandleBytes)); }

bool PreSessions::handle_ok(std::string_view handle) {
  const auto bytes = encoding::base64url_decode(handle);
  return bytes && bytes->size() == kHandleBytes;
}

std::string PreSessions::csrf_token(std::string_view handle) const {
  return encoding::base64url(dannan::identity::hmac_sha256(_key, bytes_of(std::string("lugh signin ") + std::string(handle))));
}

bool PreSessions::csrf_ok(std::string_view handle, std::string_view token) const {
  if (!handle_ok(handle)) return false;
  const auto expected = csrf_token(handle);
  return dannan::identity::constant_time_equal(bytes_of(expected), bytes_of(token));
}

std::optional<PreSession> PreSessions::find(std::string_view handle) const {
  if (!handle_ok(handle)) return std::nullopt;
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  const auto found = _held.find(key_of(handle));
  if (found == _held.end() || now - found->second.started > _lifetime) return std::nullopt;
  return found->second.pre_session;
}

void PreSessions::put(std::string_view handle, PreSession pre_session) {
  if (!handle_ok(handle)) return;
  const auto now = _time.now();
  const auto key = key_of(handle);
  dannan::contract::Lock state(_mutex);
  // The expired go first; then, if still full, the oldest.
  std::erase_if(_held, [&](const auto& one) { return now - one.second.started > _lifetime; });
  if (!_held.count(key) && _held.size() >= _most) {
    const auto oldest = std::min_element(_held.begin(), _held.end(), [](const auto& a, const auto& b) { return a.second.started < b.second.started; });
    _held.erase(oldest);
  }
  const auto found = _held.find(key);
  const auto started = found == _held.end() ? now : found->second.started;
  _held[key] = Held{std::move(pre_session), started};
}

void PreSessions::end(std::string_view handle) {
  if (!handle_ok(handle)) return;
  dannan::contract::Lock state(_mutex);
  _held.erase(key_of(handle));
}

}  // namespace lugh::session

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/challenges.h"

#include "dannan/identity/crypto.h"

namespace lugh::authn {

namespace {

constexpr std::size_t kRandomBytes = 16;
constexpr std::size_t kExpiryBytes = 8;
constexpr std::size_t kMacBytes = 16;
static_assert(kRandomBytes + kExpiryBytes + kMacBytes == Challenges::kBytes);

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

std::int64_t ticks(dannan::contract::TimePoint at) { return std::chrono::duration_cast<std::chrono::nanoseconds>(at.time_since_epoch()).count(); }

}  // namespace

Challenges::Challenges(const dannan::contract::TimeSource& time, std::chrono::seconds lifetime, std::size_t most)
    : _time(time), _lifetime(lifetime), _most(most), _key(secure_random(32)) {}

std::string Challenges::_mac(std::string_view body, std::string_view binding) const {
  // The binding's length first, so no two (body, binding) pairs make one input.
  std::string input = "lugh webauthn ";
  input += std::to_string(binding.size());
  input += ' ';
  input += binding;
  input += body;
  const auto mac = dannan::identity::hmac_sha256(_key, bytes_of(input));
  return std::string(reinterpret_cast<const char*>(mac.data()), kMacBytes);
}

std::string Challenges::issue(std::string_view binding) const {
  const auto random = dannan::identity::random_bytes(kRandomBytes);
  std::string body(random.begin(), random.end());
  const auto expires = static_cast<std::uint64_t>(ticks(_time.now() + _lifetime));
  for (int shift = 56; shift >= 0; shift -= 8) body.push_back(static_cast<char>(expires >> shift));
  return body + _mac(body, binding);
}

bool Challenges::claim(std::string_view challenge, std::string_view binding) {
  if (challenge.size() != kBytes) return false;
  const auto body = challenge.substr(0, kRandomBytes + kExpiryBytes);
  const auto mac = challenge.substr(kRandomBytes + kExpiryBytes);
  if (!dannan::identity::constant_time_equal(bytes_of(mac), bytes_of(_mac(body, binding)))) return false;
  std::uint64_t expires = 0;
  for (std::size_t i = 0; i < kExpiryBytes; ++i) expires = (expires << 8) | static_cast<unsigned char>(body[kRandomBytes + i]);
  const auto now = _time.now();
  if (static_cast<std::int64_t>(expires) <= ticks(now)) return false;
  const auto until = dannan::contract::TimePoint(std::chrono::duration_cast<dannan::contract::TimePoint::duration>(std::chrono::nanoseconds(expires)));

  dannan::contract::Lock state(_mutex);
  if (_used.contains(challenge)) return false;
  if (_used.size() >= _most) std::erase_if(_used, [&](const auto& entry) { return entry.second <= now; });
  // Full of challenges still live: refuse rather than forget one that could be replayed.
  if (_used.size() >= _most) return false;
  _used.emplace(std::string(challenge), until);
  return true;
}

void Challenges::release(std::string_view challenge) {
  dannan::contract::Lock state(_mutex);
  if (const auto found = _used.find(challenge); found != _used.end()) _used.erase(found);
}

}  // namespace lugh::authn

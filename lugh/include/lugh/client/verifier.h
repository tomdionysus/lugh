//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/client/tokens.h"

// Checks Lugh's tokens offline, for a relying party: access tokens (RFC 9068) and ID tokens
// (OpenID Connect Core 1.0, 3.1.3.7), from the issuers it trusts. Each site's Lugh is its own
// issuer (docs/architecture.md, question 14), so each trusted issuer has its own keys, which a
// key source hands in as JWKS documents (RFC 7517 section 5) and replaces as they rotate. A
// token's iss picks the keys and its kid the key; a token from an issuer not trusted, from one
// with no keys yet, or under a kid its issuer's keys do not hold, is refused and says so, so the
// key source knows to look again. Times are the injected wall clock's, a clock's skew allowed.
// What this cannot see: a revocation, which only the issuing node knows; a token is honoured
// until its exp. Thread-safe: verify from any thread while keys are replaced from another.
// Never waits.
namespace lugh::client {

struct VerifyKey;

class Verifier {
 public:
  // The most keys one issuer's JWKS may hold: a few around a rotation is usual.
  static constexpr std::size_t kMostKeys = 32;

  // Throws std::invalid_argument for no issuers, or an empty one.
  Verifier(std::vector<std::string> issuers, const dannan::contract::WallClock& wall);
  ~Verifier();
  Verifier(const Verifier&) = delete;
  Verifier& operator=(const Verifier&) = delete;

  const std::vector<std::string>& issuers() const noexcept { return _issuers; }

  // Replaces `issuer`'s keys with the P-256 and Ed25519 public keys in `jwks` that have a kid,
  // skipping any other; answers how many it took. Throws std::invalid_argument for an issuer
  // not trusted, and std::runtime_error for a document with no keys array or more than
  // kMostKeys entries, leaving the keys as they were.
  std::size_t set_keys(std::string_view issuer, const boost::json::object& jwks);

  // An access token, with `audience` among its audiences when one is given, or why not.
  std::variant<AccessToken, std::string> verify_access(std::string_view token, std::optional<std::string_view> audience = std::nullopt) const;

  // An ID token made for `client_id`, carrying `nonce` when one is given, or why not.
  std::variant<IdToken, std::string> verify_id(std::string_view token, std::string_view client_id, std::optional<std::string_view> nonce = std::nullopt) const;

 private:
  using Keys = std::shared_ptr<const std::vector<VerifyKey>>;

  // The issuer a token names and that issuer's keys, or why there are none to check it with.
  std::variant<std::pair<std::string, Keys>, std::string> _keys_for(std::string_view token) const;
  std::uint64_t _now() const { return _wall.unix_ms() / 1000; }

  const std::vector<std::string> _issuers;
  const dannan::contract::WallClock& _wall;
  mutable dannan::contract::Mutex _mutex;
  std::map<std::string, Keys, std::less<>> _keys DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::client

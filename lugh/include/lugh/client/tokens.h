//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <boost/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// What lugh_client answers for a token of Lugh's once it has checked it: an access token (RFC
// 9068) or an ID token (OpenID Connect Core 1.0, section 2). Times are Unix seconds, as the
// tokens carry them.
namespace lugh::client {

// How far apart two clocks may be: a token is still good this long after its exp and already
// good this long before its nbf.
inline constexpr std::uint64_t kClockSkewSeconds = 60;

struct AccessToken {
  boost::json::object claims;
  std::string issuer;
  std::string subject;
  std::string client_id;
  std::string jti;
  // aud, as a list whether it came as one string or an array of them.
  std::vector<std::string> audiences;
  // The scope claim split on spaces, empty pieces dropped.
  std::vector<std::string> scopes;
  // exp.
  std::uint64_t expires = 0;
  // cnf.jkt: the thumbprint of the DPoP key the token is bound to (RFC 9449).
  std::optional<std::string> jkt;
  // cnf.x5t#S256: the SHA-256 thumbprint of the certificate the token is bound to (RFC 8705),
  // decoded; a token whose value is not base64url of 32 bytes is refused.
  std::optional<std::array<std::uint8_t, 32>> x5t;
};

struct IdToken {
  boost::json::object claims;
  std::string issuer;
  std::string subject;
  std::vector<std::string> audiences;
  // exp and iat.
  std::uint64_t expires = 0;
  std::uint64_t issued_at = 0;
  std::optional<std::uint64_t> auth_time;
  std::optional<std::string> nonce;
  // The session at the issuer, for logout (OIDC Front- and Back-Channel Logout).
  std::optional<std::string> sid;
  std::optional<std::string> acr;
};

}  // namespace lugh::client

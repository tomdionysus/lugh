//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "lugh/client/jose.h"

// An access token of Lugh's, checked offline (RFC 9068): what a Lugh node and a relying party
// both ask of one before trusting it. A JWS with typ at+jwt, signed by the key its kid names;
// iss the issuer expected; sub, client_id and jti present; in its lifetime, a clock's skew either
// side; the audience asked for among its audiences; and a cnf, if it has one, that binds it to a
// key (jkt, RFC 9449) or a certificate (x5t#S256, RFC 8705). Revocation is not here: only the
// node that keeps the revoked list can see it, and anyone else honours a token until its exp.
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
  // exp, in Unix seconds.
  std::uint64_t expires = 0;
  // cnf.jkt: the thumbprint of the DPoP key the token is bound to.
  std::optional<std::string> jkt;
  // cnf.x5t#S256: the thumbprint of the certificate the token is bound to, base64url.
  std::optional<std::string> x5t;
};

// `compact`, checked against `keys` for `issuer` at `now` (Unix seconds), and for `audience`
// when one is given: the token, or why it is refused. Never waits.
std::variant<AccessToken, std::string> check_access_token(std::string_view compact, const std::vector<VerifyKey>& keys, std::string_view issuer,
                                                          std::uint64_t now, std::optional<std::string_view> audience = std::nullopt);

}  // namespace lugh::client

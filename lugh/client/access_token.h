//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "lugh/client/jose.h"
#include "lugh/client/tokens.h"

// An access token of Lugh's, checked offline (RFC 9068): what a Lugh node and a relying party
// both ask of one before trusting it. A JWS with typ at+jwt, signed by the key its kid names;
// iss the issuer expected; sub, client_id and jti present; in its lifetime, a clock's skew either
// side; the audience asked for among its audiences; and a cnf, if it has one, that binds it to a
// key (jkt, RFC 9449) or a certificate (x5t#S256, RFC 8705). Revocation is not here: only the
// node that keeps the revoked list can see it, and anyone else honours a token until its exp.
namespace lugh::client {

// `compact`, checked against `keys` for `issuer` at `now` (Unix seconds), and for `audience`
// when one is given: the token, or why it is refused. Never waits.
std::variant<AccessToken, std::string> check_access_token(std::string_view compact, const std::vector<VerifyKey>& keys, std::string_view issuer,
                                                          std::uint64_t now, std::optional<std::string_view> audience = std::nullopt);

}  // namespace lugh::client

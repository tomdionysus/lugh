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

// An ID token of Lugh's, checked by the client it was made for (OpenID Connect Core 1.0, section
// 3.1.3.7): a JWS with typ JWT (so an access token is never taken for one), signed by the key its
// kid names; iss the issuer expected; a sub; the client among its audiences, and azp naming the
// client when it has more than one audience or says azp at all; exp, a clock's skew allowed, and
// iat; and the nonce the client sent, when it sent one.
namespace lugh::client {

// `compact`, checked against `keys` for `issuer` and `client_id` at `now` (Unix seconds): the
// token, or why it is refused. Never waits.
std::variant<IdToken, std::string> check_id_token(std::string_view compact, const std::vector<VerifyKey>& keys, std::string_view issuer,
                                                  std::string_view client_id, std::uint64_t now, std::optional<std::string_view> nonce = std::nullopt);

}  // namespace lugh::client

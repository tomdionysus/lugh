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

#include "dannan/identity/signing.h"

// DPoP proofs as a client makes them (RFC 9449 section 4.2): a JWS whose header holds typ
// dpop+jwt, the key's algorithm and its public JWK, and whose claims say which request it is for
// (htm, htu), when (iat), a fresh jti, and for a request carrying an access token, that token's hash
// (ath). A token bound to the key is good only with a proof by it. Lugh asks for no DPoP nonce, so
// none is sent.
namespace lugh::client {

// The key's public JWK as a proof carries it: kty, crv, x (and y for P-256), nothing else.
boost::json::object dpop_jwk(const dannan::identity::SigningKey& key);

// A proof by `key` for `method` at `url` (no query or fragment, RFC 9449 section 4.2), made at
// `iat` (Unix seconds), with `access_token`'s hash when one is given.
std::string dpop_proof(const dannan::identity::SigningKey& key, std::string_view method, std::string_view url, std::uint64_t iat,
                       std::optional<std::string_view> access_token = std::nullopt);

}  // namespace lugh::client

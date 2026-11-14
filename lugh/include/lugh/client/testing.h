//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <string>

#include "dannan/identity/signing.h"

// For a relying party's tests: tokens signed as a Lugh issuer signs them, and the keys a Verifier
// needs to check them, so a consumer's tests prove its verification with real tokens and no
// Lugh internals. A test holds the issuer's private key; nothing here is for production.
namespace lugh::client::testing {

// An access token signed by `key` under `kid`, as Lugh signs one: typ at+jwt, ES256 or EdDSA by
// the key, `claims` as given (iss, sub, aud, client_id, exp, jti and the rest are the test's).
std::string sign_access_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims);

// An ID token, likewise: typ JWT.
std::string sign_id_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims);

// A JWKS holding `key`'s public part under `kid`, ready for Verifier::set_keys.
boost::json::object jwks(const dannan::identity::SigningKey& key, const std::string& kid);

}  // namespace lugh::client::testing

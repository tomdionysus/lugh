//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/testing.h"

#include "lugh/client/jose.h"

namespace lugh::client::testing {

std::string sign_access_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims) {
  return jws_sign(key, kid, "at+jwt", claims);
}

std::string sign_id_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims) {
  return jws_sign(key, kid, "JWT", claims);
}

boost::json::object jwks(const dannan::identity::SigningKey& key, const std::string& kid) {
  boost::json::array keys;
  keys.push_back(*public_jwk({kid, key.algorithm(), key.public_key()}));
  return {{"keys", std::move(keys)}};
}

}  // namespace lugh::client::testing

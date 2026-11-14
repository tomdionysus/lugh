//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/dpop.h"

#include "dannan/identity/crypto.h"
#include "lugh/client/jose.h"
#include "lugh/core/encoding.h"

namespace lugh::client {

boost::json::object dpop_jwk(const dannan::identity::SigningKey& key) {
  auto jwk = *public_jwk({"", key.algorithm(), key.public_key()});
  jwk.erase("kid");
  jwk.erase("use");
  jwk.erase("alg");
  return jwk;
}

std::string dpop_proof(const dannan::identity::SigningKey& key, std::string_view method, std::string_view url, std::uint64_t iat,
                       std::optional<std::string_view> access_token) {
  boost::json::object header{{"typ", "dpop+jwt"}, {"alg", dannan::identity::algorithm_name(key.algorithm())}, {"jwk", dpop_jwk(key)}};
  boost::json::object claims{{"jti", encoding::base64url(dannan::identity::random_bytes(16))}, {"htm", method}, {"htu", url}, {"iat", iat}};
  if (access_token) claims["ath"] = encoding::base64url(dannan::identity::sha256(byte_span(*access_token)).bytes);
  return jws_sign_with(key, std::move(header), claims);
}

}  // namespace lugh::client

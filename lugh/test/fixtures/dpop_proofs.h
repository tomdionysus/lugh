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

#include "dannan/identity/crypto.h"
#include "lugh/client/dpop.h"
#include "lugh/client/jose.h"
#include "lugh/core/encoding.h"

// DPoP proofs as a client makes them (RFC 9449 section 4), for the tests: a key, and proofs by
// it for a method and URL, with the access token's hash when one is given.
class DpopClient {
 public:
  explicit DpopClient(lugh::client::SigningAlgorithm algorithm = lugh::client::SigningAlgorithm::es256) : key(lugh::client::SigningKey::generate(algorithm)) {}

  boost::json::object jwk() const { return lugh::client::dpop_jwk(key); }

  // A proof; `header` and `claims` changed by the caller to make bad ones.
  std::string proof(const std::string& method, const std::string& url, std::uint64_t iat, const std::optional<std::string>& access_token = std::nullopt,
                    boost::json::object header = {}, boost::json::object claims = {}) {
    if (!header.contains("typ")) header["typ"] = "dpop+jwt";
    if (!header.contains("alg")) header["alg"] = dannan::identity::algorithm_name(key.algorithm());
    if (!header.contains("jwk")) header["jwk"] = jwk();
    if (!claims.contains("jti")) claims["jti"] = "jti-" + std::to_string(++_sequence);
    if (!claims.contains("htm")) claims["htm"] = method;
    if (!claims.contains("htu")) claims["htu"] = url;
    if (!claims.contains("iat")) claims["iat"] = iat;
    if (access_token && !claims.contains("ath")) {
      claims["ath"] = lugh::encoding::base64url(dannan::identity::sha256(lugh::byte_span(*access_token)).bytes);
    }
    return lugh::client::jws_sign_with(key, std::move(header), claims);
  }

  lugh::client::SigningKey key;

 private:
  int _sequence = 0;
};

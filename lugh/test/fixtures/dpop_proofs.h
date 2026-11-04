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
#include "lugh/core/encoding.h"
#include "lugh/tokens/jose.h"

// DPoP proofs as a client makes them (RFC 9449 section 4), for the tests: a key, and proofs by
// it for a method and URL, with the access token's hash when one is given.
class DpopClient {
 public:
  explicit DpopClient(lugh::tokens::SigningAlgorithm algorithm = lugh::tokens::SigningAlgorithm::es256) : key(lugh::tokens::SigningKey::generate(algorithm)) {}

  boost::json::object jwk() const {
    auto out = *lugh::tokens::public_jwk({"unused", key.algorithm(), key.public_key()});
    out.erase("kid");
    out.erase("use");
    out.erase("alg");
    return out;
  }

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
    const auto header_text = boost::json::serialize(header);
    const auto claims_text = boost::json::serialize(claims);
    const auto input = lugh::encoding::base64url(lugh::byte_span(header_text)) + "." + lugh::encoding::base64url(lugh::byte_span(claims_text));
    return input + "." + lugh::encoding::base64url(key.sign(lugh::byte_span(input)));
  }

  lugh::tokens::SigningKey key;

 private:
  int _sequence = 0;
};

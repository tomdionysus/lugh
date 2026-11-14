//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/access_token.h"

#include <algorithm>

#include "lugh/client/claims.h"
#include "lugh/core/encoding.h"

namespace lugh::client {

namespace {

std::vector<std::string> split_on_spaces(std::string_view text) {
  std::vector<std::string> pieces;
  while (!text.empty()) {
    const auto space = text.find(' ');
    const auto piece = text.substr(0, space);
    if (!piece.empty()) pieces.emplace_back(piece);
    if (space == std::string_view::npos) break;
    text.remove_prefix(space + 1);
  }
  return pieces;
}

}  // namespace

std::variant<AccessToken, std::string> check_access_token(std::string_view compact, const std::vector<VerifyKey>& keys, std::string_view issuer,
                                                          std::uint64_t now, std::optional<std::string_view> audience) {
  const auto jws = jws_parse(compact);
  if (!jws) return std::string("not a JWS Lugh reads");
  if (jws->typ != "at+jwt") return std::string("not an access token (typ is not at+jwt)");
  if (!jws_verify(*jws, keys)) return std::string("the signature does not verify");

  AccessToken token;
  token.claims = jws->claims;
  const auto& claims = token.claims;
  const auto iss = string_claim(claims, "iss");
  if (!iss || *iss != issuer) return std::string("not this issuer's");
  token.issuer = *iss;
  const auto sub = string_claim(claims, "sub");
  const auto client_id = string_claim(claims, "client_id");
  if (!sub || !client_id) return std::string("no sub or client_id");
  token.subject = *sub;
  token.client_id = *client_id;
  const auto jti = string_claim(claims, "jti");
  if (!jti) return std::string("no jti");
  token.jti = *jti;

  const auto exp = seconds_claim(claims, "exp");
  const auto nbf = seconds_claim(claims, "nbf");
  if (!exp) return std::string("no exp");
  if (now >= *exp + kClockSkewSeconds) return std::string("expired");
  if (nbf && now + kClockSkewSeconds < *nbf) return std::string("not yet valid");
  token.expires = *exp;

  token.audiences = audiences_claim(claims);
  if (audience && std::find(token.audiences.begin(), token.audiences.end(), *audience) == token.audiences.end()) {
    return std::string("not for this audience");
  }

  if (const auto cnf = claims.if_contains("cnf"); cnf && cnf->is_object()) {
    token.jkt = string_claim(cnf->as_object(), "jkt");
    if (const auto x5t = string_claim(cnf->as_object(), "x5t#S256")) {
      const auto bytes = encoding::base64url_decode(*x5t);
      if (!bytes || bytes->size() != 32) return std::string("bound to a certificate thumbprint that is not one");
      std::array<std::uint8_t, 32> thumbprint{};
      std::copy(bytes->begin(), bytes->end(), thumbprint.begin());
      token.x5t = thumbprint;
    }
    // A cnf that binds to nothing known is no token of Lugh's.
    if (!token.jkt && !token.x5t) return std::string("bound to something not known");
  }
  if (const auto scope = string_claim(claims, "scope")) token.scopes = split_on_spaces(*scope);
  return token;
}

}  // namespace lugh::client

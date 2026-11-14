//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/access_token.h"

namespace lugh::client {

namespace {

std::optional<std::uint64_t> seconds_claim(const boost::json::object& claims, std::string_view name) {
  const auto found = claims.if_contains(name);
  if (!found || !found->is_number()) return std::nullopt;
  const auto value = found->to_number<double>();
  if (value < 0) return std::nullopt;
  return static_cast<std::uint64_t>(value);
}

std::optional<std::string> string_claim(const boost::json::object& object, std::string_view name) {
  const auto found = object.if_contains(name);
  if (!found || !found->is_string()) return std::nullopt;
  return std::string(found->as_string());
}

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

  if (const auto aud = claims.if_contains("aud"); aud && aud->is_array()) {
    for (const auto& one : aud->as_array()) {
      if (one.is_string()) token.audiences.emplace_back(one.as_string());
    }
  } else if (aud && aud->is_string()) {
    token.audiences.emplace_back(aud->as_string());
  }
  if (audience) {
    bool found = false;
    for (const auto& one : token.audiences) found = found || one == *audience;
    if (!found) return std::string("not for this audience");
  }

  if (const auto cnf = claims.if_contains("cnf"); cnf && cnf->is_object()) {
    token.jkt = string_claim(cnf->as_object(), "jkt");
    token.x5t = string_claim(cnf->as_object(), "x5t#S256");
    // A cnf that binds to nothing known is no token of Lugh's.
    if (!token.jkt && !token.x5t) return std::string("bound to something not known");
  }
  if (const auto scope = string_claim(claims, "scope")) token.scopes = split_on_spaces(*scope);
  return token;
}

}  // namespace lugh::client

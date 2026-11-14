//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/id_token.h"

#include <algorithm>

#include "lugh/client/claims.h"

namespace lugh::client {

std::variant<IdToken, std::string> check_id_token(std::string_view compact, const std::vector<VerifyKey>& keys, std::string_view issuer,
                                                  std::string_view client_id, std::uint64_t now, std::optional<std::string_view> nonce) {
  const auto jws = jws_parse(compact);
  if (!jws) return std::string("not a JWS Lugh reads");
  if (jws->typ != "JWT") return std::string("not an ID token (typ is not JWT)");
  if (!jws_verify(*jws, keys)) return std::string("the signature does not verify");

  IdToken token;
  token.claims = jws->claims;
  const auto& claims = token.claims;
  const auto iss = string_claim(claims, "iss");
  if (!iss || *iss != issuer) return std::string("not this issuer's");
  token.issuer = *iss;
  const auto sub = string_claim(claims, "sub");
  if (!sub) return std::string("no sub");
  token.subject = *sub;

  token.audiences = audiences_claim(claims);
  if (std::find(token.audiences.begin(), token.audiences.end(), client_id) == token.audiences.end()) return std::string("not for this client");
  const auto azp = string_claim(claims, "azp");
  if (token.audiences.size() > 1 && !azp) return std::string("several audiences and no azp");
  if (claims.contains("azp") && azp != client_id) return std::string("azp is another client");

  const auto exp = seconds_claim(claims, "exp");
  const auto iat = seconds_claim(claims, "iat");
  if (!exp) return std::string("no exp");
  if (!iat) return std::string("no iat");
  if (now >= *exp + kClockSkewSeconds) return std::string("expired");
  token.expires = *exp;
  token.issued_at = *iat;

  token.nonce = string_claim(claims, "nonce");
  if (nonce && token.nonce != *nonce) return std::string("not the nonce sent");
  token.auth_time = seconds_claim(claims, "auth_time");
  token.sid = string_claim(claims, "sid");
  token.acr = string_claim(claims, "acr");
  return token;
}

}  // namespace lugh::client

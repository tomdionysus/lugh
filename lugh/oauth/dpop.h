//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "dannan/contract/time_source.h"
#include "lugh/core/outcome.h"
#include "lugh/http/caller.h"
#include "lugh/http/http_types.h"
#include "lugh/oauth/expiring.h"
#include "lugh/oauth/issuer.h"
#include "lugh/tokens/jose.h"

// DPoP (RFC 9449): a token bound to a key its client holds, so a token copied without the key
// is useless (docs/architecture.md, "OAuth profile": token binding).
namespace lugh::oauth {

// RFC 7638: the SHA-256 thumbprint of a public key's JWK, base64url: what `cnf.jkt` names.
std::string jwk_thumbprint(const tokens::VerifyKey& key);

// A DPoP proof, its signature checked against the key it carries.
struct Proof {
  std::string jkt;
  std::string htm;
  std::string htu;
  std::string jti;
  std::uint64_t iat = 0;
  std::optional<std::string> ath;
};

// The proof in `text`: a JWS whose header holds typ dpop+jwt, alg ES256 or EdDSA, and a public
// jwk and nothing else, signed by that key, with jti, htm, htu and iat. Nothing otherwise.
std::optional<Proof> parse_proof(std::string_view text);

// Checks proofs as they arrive: signed, for this request's method and URL, made within five
// minutes either way, never seen before on this node, and for an access token the hash of
// that token in `ath`. Safe from any number of threads.
class DpopChecker {
 public:
  static constexpr const char* kHeader = "DPoP";
  static constexpr std::uint64_t kWindow = 300;

  DpopChecker(const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall);

  // invalid, saying why, for a proof that is not good for this request.
  Outcome<Proof> check(std::string_view proof, std::string_view method, std::string_view url, std::optional<std::string_view> access_token = std::nullopt);

 private:
  const dannan::contract::WallClock& _wall;
  Expiring<bool> _seen;
};

// The access token a request presents, checked: `Authorization: Bearer` for a token bound to no
// key, `Authorization: DPoP` with a proof by the token's key for one bound (RFC 9449 section 7),
// the proof made for this method and `url_base` + the request's path. With `audience`, the
// token must name it. Nothing for any other request, or any token presented the wrong way.
std::optional<Bearer> presented_token(const TokenIssuer& issuer, DpopChecker& dpop, const http::HttpRequest& request, std::string_view url_base,
                                      std::optional<std::string_view> audience);

// The API's caller for a presented token: one of Lugh's access tokens with `lugh` among its
// audiences, a person's or a client's own, holding its scopes. Nothing for any other.
std::optional<http::Caller> api_caller(const TokenIssuer& issuer, DpopChecker& dpop, const http::HttpRequest& request);

}  // namespace lugh::oauth

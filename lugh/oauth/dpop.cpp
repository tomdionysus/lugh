//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/dpop.h"

#include <boost/json.hpp>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/http/client_certificate.h"

namespace lugh::oauth {

namespace {

std::optional<boost::json::object> json_object(std::string_view encoded) {
  const auto bytes = encoding::base64url_decode(encoded);
  if (!bytes) return std::nullopt;
  boost::system::error_code ec;
  auto parsed = boost::json::parse(std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()), ec);
  if (ec || !parsed.is_object()) return std::nullopt;
  return std::move(parsed.as_object());
}

std::optional<std::string> string_of(const boost::json::object& object, std::string_view name) {
  const auto found = object.if_contains(name);
  if (!found || !found->is_string()) return std::nullopt;
  return std::string(found->as_string());
}

}  // namespace

std::string jwk_thumbprint(const tokens::VerifyKey& key) {
  const auto jwk = tokens::public_jwk(key);
  if (!jwk) return {};
  // RFC 7638 section 3: the required members only, in lexical order, no whitespace.
  std::string canonical;
  if (key.algorithm == tokens::SigningAlgorithm::es256) {
    canonical = R"({"crv":"P-256","kty":"EC","x":")" + std::string(jwk->at("x").as_string()) + R"(","y":")" + std::string(jwk->at("y").as_string()) + "\"}";
  } else {
    canonical = R"({"crv":"Ed25519","kty":"OKP","x":")" + std::string(jwk->at("x").as_string()) + "\"}";
  }
  return encoding::base64url(dannan::identity::sha256(byte_span(canonical)).bytes);
}

std::optional<Proof> parse_proof(std::string_view text) {
  if (text.size() > tokens::kMostJwsBytes) return std::nullopt;
  const auto first = text.find('.');
  const auto second = first == std::string_view::npos ? std::string_view::npos : text.find('.', first + 1);
  if (second == std::string_view::npos || text.find('.', second + 1) != std::string_view::npos) return std::nullopt;
  const auto header = json_object(text.substr(0, first));
  const auto claims = json_object(text.substr(first + 1, second - first - 1));
  const auto signature = encoding::base64url_decode(text.substr(second + 1));
  if (!header || !claims || !signature || signature->size() != 64) return std::nullopt;

  for (const auto& member : *header) {
    if (member.key() != "typ" && member.key() != "alg" && member.key() != "jwk") return std::nullopt;
  }
  if (string_of(*header, "typ") != "dpop+jwt") return std::nullopt;
  const auto jwk = header->if_contains("jwk");
  if (!jwk || !jwk->is_object()) return std::nullopt;
  const auto key = tokens::from_jwk(jwk->as_object());
  if (!key) return std::nullopt;
  if (string_of(*header, "alg") != std::string(dannan::identity::algorithm_name(key->algorithm))) return std::nullopt;
  if (!dannan::identity::verify(key->algorithm, key->public_key, byte_span(text.substr(0, second)), *signature)) return std::nullopt;

  Proof proof;
  proof.jkt = jwk_thumbprint(*key);
  const auto htm = string_of(*claims, "htm");
  const auto htu = string_of(*claims, "htu");
  const auto jti = string_of(*claims, "jti");
  const auto iat = claims->if_contains("iat");
  if (!htm || !htu || !jti || jti->empty() || jti->size() > 256 || !iat || !iat->is_number() || iat->to_number<double>() < 0) return std::nullopt;
  proof.htm = *htm;
  proof.htu = *htu;
  proof.jti = *jti;
  proof.iat = static_cast<std::uint64_t>(iat->to_number<double>());
  proof.ath = string_of(*claims, "ath");
  return proof;
}

DpopChecker::DpopChecker(const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall)
    : _wall(wall), _seen(time, std::chrono::seconds(2 * kWindow + 60), 100000) {}

Outcome<Proof> DpopChecker::check(std::string_view text, std::string_view method, std::string_view url, std::optional<std::string_view> access_token) {
  using Answer = Outcome<Proof>;
  const auto proof = parse_proof(text);
  if (!proof) return Answer::failure(Fault::invalid, "the DPoP proof is not a signed dpop+jwt carrying its public key");
  if (proof->htm != method) return Answer::failure(Fault::invalid, "the DPoP proof is for another method");
  if (proof->htu != url) return Answer::failure(Fault::invalid, "the DPoP proof is for another URL");
  const auto now = _wall.unix_ms() / 1000;
  if (proof->iat + kWindow < now || proof->iat > now + kWindow) return Answer::failure(Fault::invalid, "the DPoP proof is too old or from the future");
  if (access_token) {
    const auto hash = encoding::base64url(dannan::identity::sha256(byte_span(*access_token)).bytes);
    if (!proof->ath || *proof->ath != hash) return Answer::failure(Fault::invalid, "the DPoP proof is not for this access token");
  }
  if (!_seen.put_as(proof->jkt + " " + proof->jti, true)) return Answer::failure(Fault::invalid, "the DPoP proof was used before");
  return Answer::success(*proof);
}

std::optional<Bearer> presented_token(const TokenIssuer& issuer, DpopChecker& dpop, const http::HttpRequest& request, std::string_view url_base,
                                      std::optional<std::string_view> audience) {
  const auto authorization = request.find(http::field::authorization);
  if (authorization == request.end()) return std::nullopt;
  const std::string_view value(authorization->value());
  const bool bound = value.rfind("DPoP ", 0) == 0;
  if (!bound && value.rfind("Bearer ", 0) != 0) return std::nullopt;
  const auto token = value.substr(bound ? 5 : 7);
  auto bearer = issuer.verify(token, audience);
  if (!bearer) return std::nullopt;
  // A bound token is never a bearer token: presented without its key, it is refused.
  if (bearer->jkt.has_value() != bound) return std::nullopt;
  // A certificate-bound token (RFC 8705 section 3) is good only on a connection presenting
  // that certificate.
  if (bearer->x5t) {
    const auto certificate = http::client_certificate(request);
    if (!certificate || certificate->thumbprint != *bearer->x5t) return std::nullopt;
  }
  if (!bound) return bearer;
  const auto proof = request.find(DpopChecker::kHeader);
  if (proof == request.end()) return std::nullopt;
  const std::string_view target(request.target());
  const auto path = target.substr(0, target.find('?'));
  const auto checked =
      dpop.check(std::string_view(proof->value()), std::string(http::to_string(request.method())), std::string(url_base) + std::string(path), token);
  if (!checked.ok() || checked.value.jkt != *bearer->jkt) return std::nullopt;
  return bearer;
}

std::optional<http::Caller> api_caller(const TokenIssuer& issuer, DpopChecker& dpop, const http::HttpRequest& request) {
  const auto bearer = presented_token(issuer, dpop, request, issuer.issuer(), "lugh");
  if (!bearer) return std::nullopt;
  return http::Caller{bearer->service ? http::Caller::Kind::service : http::Caller::Kind::user, bearer->subject, bearer->scopes};
}

}  // namespace lugh::oauth

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/jose.h"

#include <algorithm>
#include <array>
#include <span>

#include "lugh/core/encoding.h"

namespace lugh::client {

namespace {

// The fixed DER around each public key (RFC 5480 for P-256, uncompressed point; RFC 8410 for
// Ed25519): the SubjectPublicKeyInfo is this prefix and the key's bytes.
constexpr std::array<unsigned char, 26> kP256Prefix{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                                                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
constexpr std::array<unsigned char, 12> kEd25519Prefix{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

template <std::size_t N>
bool starts_with(std::span<const unsigned char> bytes, const std::array<unsigned char, N>& prefix) {
  return bytes.size() >= N && std::equal(prefix.begin(), prefix.end(), bytes.begin());
}

std::optional<std::string> string_member(const boost::json::object& object, std::string_view name) {
  const auto found = object.if_contains(name);
  if (!found || !found->is_string()) return std::nullopt;
  return std::string(found->as_string());
}

std::optional<boost::json::object> json_object(std::string_view encoded) {
  const auto bytes = encoding::base64url_decode(encoded);
  if (!bytes) return std::nullopt;
  boost::system::error_code ec;
  auto parsed = boost::json::parse(std::string_view(reinterpret_cast<const char*>(bytes->data()), bytes->size()), ec);
  if (ec || !parsed.is_object()) return std::nullopt;
  return std::move(parsed.as_object());
}

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

}  // namespace

std::optional<boost::json::object> public_jwk(const VerifyKey& key) {
  const std::span<const unsigned char> der(key.public_key);
  boost::json::object out;
  if (key.algorithm == SigningAlgorithm::es256) {
    if (der.size() != kP256Prefix.size() + 65 || !starts_with(der, kP256Prefix) || der[kP256Prefix.size()] != 0x04) return std::nullopt;
    out["kty"] = "EC";
    out["crv"] = "P-256";
    out["x"] = encoding::base64url(der.subspan(kP256Prefix.size() + 1, 32));
    out["y"] = encoding::base64url(der.subspan(kP256Prefix.size() + 33, 32));
  } else {
    if (der.size() != kEd25519Prefix.size() + 32 || !starts_with(der, kEd25519Prefix)) return std::nullopt;
    out["kty"] = "OKP";
    out["crv"] = "Ed25519";
    out["x"] = encoding::base64url(der.subspan(kEd25519Prefix.size(), 32));
  }
  out["kid"] = key.kid;
  out["alg"] = dannan::identity::algorithm_name(key.algorithm);
  out["use"] = "sig";
  return out;
}

std::optional<Bytes> public_key_der(SigningAlgorithm algorithm, std::span<const unsigned char> x, std::span<const unsigned char> y) {
  Bytes out;
  if (algorithm == SigningAlgorithm::es256) {
    if (x.size() != 32 || y.size() != 32) return std::nullopt;
    out.assign(kP256Prefix.begin(), kP256Prefix.end());
    out.push_back(0x04);
    out.insert(out.end(), x.begin(), x.end());
    out.insert(out.end(), y.begin(), y.end());
  } else {
    if (x.size() != 32 || !y.empty()) return std::nullopt;
    out.assign(kEd25519Prefix.begin(), kEd25519Prefix.end());
    out.insert(out.end(), x.begin(), x.end());
  }
  // A point not on the curve is no key: Dannan's parser says which algorithm a
  // SubjectPublicKeyInfo is for only when OpenSSL can read it.
  if (dannan::identity::algorithm_of_public_key(out) != algorithm) return std::nullopt;
  return out;
}

std::optional<VerifyKey> from_jwk(const boost::json::object& jwk) {
  if (jwk.contains("d")) return std::nullopt;
  const auto kty = string_member(jwk, "kty");
  const auto crv = string_member(jwk, "crv");
  const auto x = string_member(jwk, "x");
  if (!kty || !crv || !x) return std::nullopt;
  const auto x_bytes = encoding::base64url_decode(*x);
  if (!x_bytes || x_bytes->size() != 32) return std::nullopt;

  VerifyKey key;
  key.kid = string_member(jwk, "kid").value_or("");
  std::optional<Bytes> der;
  if (*kty == "EC" && *crv == "P-256") {
    const auto y = string_member(jwk, "y");
    const auto y_bytes = y ? encoding::base64url_decode(*y) : std::nullopt;
    if (!y_bytes) return std::nullopt;
    key.algorithm = SigningAlgorithm::es256;
    der = public_key_der(key.algorithm, *x_bytes, *y_bytes);
  } else if (*kty == "OKP" && *crv == "Ed25519") {
    key.algorithm = SigningAlgorithm::ed25519;
    der = public_key_der(key.algorithm, *x_bytes, {});
  }
  if (!der) return std::nullopt;
  key.public_key = std::move(*der);
  if (const auto alg = string_member(jwk, "alg"); alg && *alg != dannan::identity::algorithm_name(key.algorithm)) return std::nullopt;
  return key;
}

std::string jws_sign(const SigningKey& key, const std::string& kid, std::string_view typ, const boost::json::object& claims) {
  boost::json::object header;
  header["alg"] = dannan::identity::algorithm_name(key.algorithm());
  header["kid"] = kid;
  header["typ"] = typ;
  return jws_sign_with(key, std::move(header), claims);
}

std::string jws_sign_with(const SigningKey& key, boost::json::object header, const boost::json::object& claims) {
  if (!header.contains("alg")) header["alg"] = dannan::identity::algorithm_name(key.algorithm());
  const auto header_text = boost::json::serialize(header);
  const auto claims_text = boost::json::serialize(claims);
  const auto input = encoding::base64url(bytes_of(header_text)) + "." + encoding::base64url(bytes_of(claims_text));
  const auto signature = key.sign(bytes_of(input));
  return input + "." + encoding::base64url(signature);
}

std::optional<Jws> jws_parse(std::string_view compact) {
  if (compact.size() > kMostJwsBytes) return std::nullopt;
  const auto first = compact.find('.');
  if (first == std::string_view::npos) return std::nullopt;
  const auto second = compact.find('.', first + 1);
  if (second == std::string_view::npos || compact.find('.', second + 1) != std::string_view::npos) return std::nullopt;

  Jws jws;
  auto header = json_object(compact.substr(0, first));
  auto claims = json_object(compact.substr(first + 1, second - first - 1));
  auto signature = encoding::base64url_decode(compact.substr(second + 1));
  if (!header || !claims || !signature || signature->size() != 64) return std::nullopt;

  for (const auto& member : *header) {
    if (member.key() != "alg" && member.key() != "kid" && member.key() != "typ") return std::nullopt;
  }
  const auto alg = string_member(*header, "alg");
  const auto kid = string_member(*header, "kid");
  if (!alg || !kid || kid->empty()) return std::nullopt;
  if (*alg == "ES256") {
    jws.algorithm = SigningAlgorithm::es256;
  } else if (*alg == "EdDSA") {
    jws.algorithm = SigningAlgorithm::ed25519;
  } else {
    return std::nullopt;
  }
  if (header->contains("typ") && !string_member(*header, "typ")) return std::nullopt;
  jws.typ = string_member(*header, "typ").value_or("");
  jws.kid = *kid;
  jws.header = std::move(*header);
  jws.claims = std::move(*claims);
  jws.signing_input = std::string(compact.substr(0, second));
  jws.signature = std::move(*signature);
  return jws;
}

bool jws_verify(const Jws& jws, const std::vector<VerifyKey>& keys) {
  for (const auto& key : keys) {
    if (key.kid != jws.kid) continue;
    if (key.algorithm != jws.algorithm) return false;
    return dannan::identity::verify(key.algorithm, key.public_key, bytes_of(jws.signing_input), jws.signature);
  }
  return false;
}

}  // namespace lugh::client

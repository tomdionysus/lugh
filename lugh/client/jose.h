//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/identity/signing.h"
#include "lugh/core/secure_bytes.h"

// JOSE, as much as Lugh's tokens need and no more: a public key as a JWK (RFC 7517, 7518
// section 6.2, RFC 8037), and a JWS in compact form (RFC 7515) signed with ES256 or EdDSA.
// The signatures are Dannan's (dannan/identity/signing.h); the framing is Lugh's, since
// token verification stays Lugh's (the maintainer, 2026-11-04). Nothing here accepts "none", an HMAC,
// RSA, a key carried in a header (jwk, jku, x5u), or a header Lugh does not understand.
namespace lugh::tokens {

using dannan::identity::SigningAlgorithm;
using dannan::identity::SigningKey;

// A key that verifies: its kid, algorithm and SubjectPublicKeyInfo (DER).
struct VerifyKey {
  std::string kid;
  SigningAlgorithm algorithm = SigningAlgorithm::es256;
  Bytes public_key;
};

// The public JWK of `key`: kty, crv, x (and y for P-256), with kid, alg and use "sig".
// Nothing for a SubjectPublicKeyInfo that is not P-256 or Ed25519.
std::optional<boost::json::object> public_jwk(const VerifyKey& key);

// The key a public JWK names; nothing for anything but a P-256 or Ed25519 public key, and for
// a JWK that holds a private part.
std::optional<VerifyKey> from_jwk(const boost::json::object& jwk);

// The longest JWS Lugh reads: a token is kept under 8 KiB (TODO/2026-11-04-oauth.md).
inline constexpr std::size_t kMostJwsBytes = 16 * 1024;

// `claims` signed by `key` under `kid`, with `typ` in the header ("at+jwt" for an access
// token, "JWT" for an ID token, "logout+jwt" for a logout token).
std::string jws_sign(const SigningKey& key, const std::string& kid, std::string_view typ, const boost::json::object& claims);

// A compact JWS, taken apart and not yet verified.
struct Jws {
  boost::json::object header;
  boost::json::object claims;
  std::string kid;
  std::string typ;
  SigningAlgorithm algorithm = SigningAlgorithm::es256;
  // The first two parts as written, which the signature covers.
  std::string signing_input;
  Bytes signature;
};

// Nothing for anything that is not three base64url parts, a header and claims that are JSON
// objects, alg ES256 or EdDSA, a kid, and no header member but alg, kid and typ.
std::optional<Jws> jws_parse(std::string_view compact);

// Whether the JWS is signed by the key its kid names, of the algorithm its header names.
bool jws_verify(const Jws& jws, const std::vector<VerifyKey>& keys);

}  // namespace lugh::tokens

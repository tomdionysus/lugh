//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "lugh/core/secure_bytes.h"
#include "lugh/webauthn/cbor.h"

// A credential's public key as a COSE key (RFC 9052 section 7, RFC 9053, RFC 8230), the three
// kinds Lugh accepts (the maintainer, 2026-11-15):
// - ES256: kty EC2 (2), alg -7, crv P-256 (1), x and y of 32 bytes each;
// - EdDSA: kty OKP (1), alg -8, crv Ed25519 (6), x of 32 bytes;
// - RS256: kty RSA (3), alg -257, n and e as big-endian bytes. Dannan's verify_rs256 refuses
//   a modulus under 2048 or over 8192 bits, and an even or small exponent; this refuses an
//   empty one.
// Anything else is refused:
// - another algorithm, or no alg at all;
// - a curve that does not match its algorithm;
// - a private part (d, or RSA's p, q, dP, dQ, qInv or other primes);
// - a key_ops that does not allow verifying;
// - a coordinate of the wrong length;
// - a point that is not on its curve.
namespace lugh::webauthn {

struct PublicKey {
  enum class Kind : std::uint8_t { es256, eddsa, rs256 };
  Kind kind = Kind::es256;
  // ES256 and EdDSA: the SubjectPublicKeyInfo (DER), as Dannan's verify() takes it.
  Bytes der;
  // RS256: the modulus and public exponent, big-endian.
  std::string modulus;
  std::string exponent;

  // The COSE algorithm: -7, -8 or -257.
  std::int64_t algorithm() const;
};

inline constexpr std::int64_t kEs256 = -7;
inline constexpr std::int64_t kEdDsa = -8;
inline constexpr std::int64_t kRs256 = -257;

std::optional<PublicKey> public_key(const cbor::Value& cose);

}  // namespace lugh::webauthn

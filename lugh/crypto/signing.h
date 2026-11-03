//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <span>
#include <string_view>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"

namespace lugh::crypto {

// The two token signature algorithms: ES256 by default, because every client library has
// it, and EdDSA over Ed25519 for the clients that ask.
enum class SignatureAlgorithm { es256, ed25519 };

// The JOSE name: "ES256" or "EdDSA".
std::string_view jose_name(SignatureAlgorithm algorithm);

class VerifyKey;

// A private signing key. Copies share one OpenSSL key, which is safe to sign with from
// several threads. Signatures are in JOSE form: Ed25519's 64 bytes as they are, ECDSA's as
// r || s, 32 bytes each, not DER.
class SigningKey {
 public:
  // No key: what a failed Result holds. It signs nothing.
  SigningKey() = default;

  static Result<SigningKey> generate(SignatureAlgorithm algorithm);

  // From PKCS#8 DER, as pkcs8() writes it. A key of another algorithm or curve is refused.
  static Result<SigningKey> from_pkcs8(SignatureAlgorithm algorithm, std::span<const unsigned char> der);

  SignatureAlgorithm algorithm() const { return _algorithm; }

  // The private key, PKCS#8 DER, for sealing. Never for anything else.
  Result<SecureBytes> pkcs8() const;

  VerifyKey verify_key() const;

  Result<Bytes> sign(std::span<const unsigned char> message) const;

 private:
  SigningKey(SignatureAlgorithm algorithm, std::shared_ptr<EVP_PKEY> key) : _algorithm(algorithm), _key(std::move(key)) {}

  SignatureAlgorithm _algorithm = SignatureAlgorithm::es256;
  std::shared_ptr<EVP_PKEY> _key;
};

// A public key, for verifying.
class VerifyKey {
 public:
  // No key: it verifies nothing.
  VerifyKey() = default;

  // From the raw public key, as public_key() writes it: Ed25519's 32 bytes, or a P-256
  // point uncompressed (0x04 || x || y, 65 bytes), which is what a JWK's x and y make. A
  // point not on the curve is refused.
  static Result<VerifyKey> from_public(SignatureAlgorithm algorithm, std::span<const unsigned char> raw);

  SignatureAlgorithm algorithm() const { return _algorithm; }

  Bytes public_key() const;

  // False for anything but a valid signature of this message by this key, including a
  // signature of the wrong length or form.
  bool verify(std::span<const unsigned char> message, std::span<const unsigned char> signature) const;

 private:
  friend class SigningKey;
  VerifyKey(SignatureAlgorithm algorithm, std::shared_ptr<EVP_PKEY> key) : _algorithm(algorithm), _key(std::move(key)) {}

  SignatureAlgorithm _algorithm = SignatureAlgorithm::es256;
  std::shared_ptr<EVP_PKEY> _key;
};

}  // namespace lugh::crypto

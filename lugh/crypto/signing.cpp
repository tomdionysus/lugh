//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/crypto/signing.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <climits>
#include <cstring>

namespace lugh::crypto {

namespace {

constexpr std::size_t kEd25519PublicBytes = 32;
constexpr std::size_t kP256PointBytes = 65;
constexpr std::size_t kP256ScalarBytes = 32;
constexpr std::size_t kSignatureBytes = 64;

std::shared_ptr<EVP_PKEY> own(EVP_PKEY* key) { return std::shared_ptr<EVP_PKEY>(key, &EVP_PKEY_free); }

using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

bool fits_int(std::size_t size) { return size <= static_cast<std::size_t>(INT_MAX); }

// Whether an OpenSSL key is the one the algorithm names, curve and all.
bool is(SignatureAlgorithm algorithm, EVP_PKEY* key) {
  if (algorithm == SignatureAlgorithm::ed25519) return EVP_PKEY_is_a(key, "ED25519") == 1;
  if (EVP_PKEY_is_a(key, "EC") != 1) return false;
  char group[64] = {};
  std::size_t length = 0;
  if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &length) != 1) return false;
  return std::strcmp(group, "prime256v1") == 0 || std::strcmp(group, "P-256") == 0;
}

// ECDSA's DER signature to JOSE's r || s.
std::optional<Bytes> der_to_jose(std::span<const unsigned char> der) {
  const unsigned char* cursor = der.data();
  std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> signature(d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der.size())), &ECDSA_SIG_free);
  if (!signature) return std::nullopt;

  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(signature.get(), &r, &s);

  Bytes out(kSignatureBytes);
  if (BN_bn2binpad(r, out.data(), kP256ScalarBytes) != static_cast<int>(kP256ScalarBytes)) return std::nullopt;
  if (BN_bn2binpad(s, out.data() + kP256ScalarBytes, kP256ScalarBytes) != static_cast<int>(kP256ScalarBytes)) return std::nullopt;
  return out;
}

// And back, for OpenSSL to verify.
std::optional<Bytes> jose_to_der(std::span<const unsigned char> jose) {
  if (jose.size() != kSignatureBytes) return std::nullopt;

  std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> signature(ECDSA_SIG_new(), &ECDSA_SIG_free);
  if (!signature) return std::nullopt;
  BIGNUM* r = BN_bin2bn(jose.data(), kP256ScalarBytes, nullptr);
  BIGNUM* s = BN_bin2bn(jose.data() + kP256ScalarBytes, kP256ScalarBytes, nullptr);
  if (r == nullptr || s == nullptr || ECDSA_SIG_set0(signature.get(), r, s) != 1) {
    BN_free(r);
    BN_free(s);
    return std::nullopt;
  }

  unsigned char* der = nullptr;
  const int length = i2d_ECDSA_SIG(signature.get(), &der);
  if (length <= 0) return std::nullopt;
  Bytes out(der, der + length);
  OPENSSL_free(der);
  return out;
}

// SHA-256 for ECDSA; none for Ed25519, which hashes inside.
const char* digest_for(SignatureAlgorithm algorithm) { return algorithm == SignatureAlgorithm::es256 ? "SHA256" : nullptr; }

}  // namespace

std::string_view jose_name(SignatureAlgorithm algorithm) { return algorithm == SignatureAlgorithm::es256 ? "ES256" : "EdDSA"; }

Result<SigningKey> SigningKey::generate(SignatureAlgorithm algorithm) {
  EVP_PKEY* key =
      algorithm == SignatureAlgorithm::ed25519 ? EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519") : EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (key == nullptr) return Result<SigningKey>::failure("cannot generate a key");
  return Result<SigningKey>::success(SigningKey(algorithm, own(key)));
}

Result<SigningKey> SigningKey::from_pkcs8(SignatureAlgorithm algorithm, std::span<const unsigned char> der) {
  using Answer = Result<SigningKey>;
  if (der.empty() || !fits_int(der.size())) return Answer::failure("not a PKCS#8 key");

  const unsigned char* cursor = der.data();
  EVP_PKEY* raw = d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(der.size()));
  if (raw == nullptr) return Answer::failure("not a PKCS#8 key");
  auto key = own(raw);

  // Trailing bytes mean this is not what pkcs8() wrote.
  if (cursor != der.data() + der.size()) return Answer::failure("not a PKCS#8 key: bytes after it");
  if (!is(algorithm, key.get())) return Answer::failure(std::string("not an ") + std::string(jose_name(algorithm)) + " key");

  return Answer::success(SigningKey(algorithm, std::move(key)));
}

Result<SecureBytes> SigningKey::pkcs8() const {
  using Answer = Result<SecureBytes>;
  if (!_key) return Answer::failure("no key");

  std::unique_ptr<OSSL_ENCODER_CTX, decltype(&OSSL_ENCODER_CTX_free)> encoder(
      OSSL_ENCODER_CTX_new_for_pkey(_key.get(), EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", nullptr), &OSSL_ENCODER_CTX_free);
  if (!encoder) return Answer::failure("cannot encode the key");

  unsigned char* data = nullptr;
  std::size_t length = 0;
  if (OSSL_ENCODER_to_data(encoder.get(), &data, &length) != 1 || data == nullptr) return Answer::failure("cannot encode the key");

  SecureBytes out(data, data + length);
  OPENSSL_clear_free(data, length);
  return Answer::success(std::move(out));
}

VerifyKey SigningKey::verify_key() const { return VerifyKey(_algorithm, _key); }

Result<Bytes> SigningKey::sign(std::span<const unsigned char> message) const {
  using Answer = Result<Bytes>;
  if (!_key) return Answer::failure("no key");
  if (!fits_int(message.size())) return Answer::failure("message too large to sign");

  DigestContext context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!context) return Answer::failure("signing: out of memory");
  if (EVP_DigestSignInit_ex(context.get(), nullptr, digest_for(_algorithm), nullptr, nullptr, _key.get(), nullptr) != 1) {
    return Answer::failure("cannot start signing");
  }

  std::size_t length = 0;
  if (EVP_DigestSign(context.get(), nullptr, &length, message.data(), message.size()) != 1) return Answer::failure("cannot size the signature");
  Bytes signature(length);
  if (EVP_DigestSign(context.get(), signature.data(), &length, message.data(), message.size()) != 1) return Answer::failure("cannot sign");
  signature.resize(length);

  if (_algorithm == SignatureAlgorithm::ed25519) {
    if (signature.size() != kSignatureBytes) return Answer::failure("Ed25519 signature of the wrong length");
    return Answer::success(std::move(signature));
  }

  auto jose = der_to_jose(signature);
  if (!jose) return Answer::failure("cannot convert the ECDSA signature");
  return Answer::success(std::move(*jose));
}

Result<VerifyKey> VerifyKey::from_public(SignatureAlgorithm algorithm, std::span<const unsigned char> raw) {
  using Answer = Result<VerifyKey>;

  if (algorithm == SignatureAlgorithm::ed25519) {
    if (raw.size() != kEd25519PublicBytes) return Answer::failure("an Ed25519 public key is 32 bytes");
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr, raw.data(), raw.size());
    if (key == nullptr) return Answer::failure("not an Ed25519 public key");
    return Answer::success(VerifyKey(algorithm, own(key)));
  }

  if (raw.size() != kP256PointBytes || raw[0] != 0x04) return Answer::failure("a P-256 public key is an uncompressed point, 65 bytes");

  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> builder(OSSL_PARAM_BLD_new(), &OSSL_PARAM_BLD_free);
  if (!builder || OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
      OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY, raw.data(), raw.size()) != 1) {
    return Answer::failure("cannot build a P-256 key");
  }
  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(builder.get()), &OSSL_PARAM_free);
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), &EVP_PKEY_CTX_free);
  if (!params || !context || EVP_PKEY_fromdata_init(context.get()) != 1) return Answer::failure("cannot build a P-256 key");

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_fromdata(context.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) != 1 || key == nullptr) return Answer::failure("not a P-256 public key");
  auto owned = own(key);

  // fromdata takes the point as given; the check that it is on the curve is a separate step.
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> check(EVP_PKEY_CTX_new_from_pkey(nullptr, owned.get(), nullptr), &EVP_PKEY_CTX_free);
  if (!check || EVP_PKEY_public_check(check.get()) != 1) return Answer::failure("not a point on P-256");

  return Answer::success(VerifyKey(algorithm, std::move(owned)));
}

Bytes VerifyKey::public_key() const {
  if (!_key) return {};
  if (_algorithm == SignatureAlgorithm::ed25519) {
    Bytes out(kEd25519PublicBytes);
    std::size_t length = out.size();
    if (EVP_PKEY_get_raw_public_key(_key.get(), out.data(), &length) != 1 || length != kEd25519PublicBytes) return {};
    return out;
  }

  Bytes out(kP256PointBytes);
  std::size_t length = 0;
  if (EVP_PKEY_get_octet_string_param(_key.get(), OSSL_PKEY_PARAM_PUB_KEY, out.data(), out.size(), &length) != 1 || length != kP256PointBytes) return {};
  return out;
}

bool VerifyKey::verify(std::span<const unsigned char> message, std::span<const unsigned char> signature) const {
  if (!_key || signature.size() != kSignatureBytes || !fits_int(message.size())) return false;

  Bytes der;
  std::span<const unsigned char> presented = signature;
  if (_algorithm == SignatureAlgorithm::es256) {
    auto converted = jose_to_der(signature);
    if (!converted) return false;
    der = std::move(*converted);
    presented = der;
  }

  DigestContext context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!context) return false;
  if (EVP_DigestVerifyInit_ex(context.get(), nullptr, digest_for(_algorithm), nullptr, nullptr, _key.get(), nullptr) != 1) return false;
  return EVP_DigestVerify(context.get(), presented.data(), presented.size(), message.data(), message.size()) == 1;
}

}  // namespace lugh::crypto

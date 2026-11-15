//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/webauthn/cose.h"

#include <span>

#include "lugh/client/jose.h"

namespace lugh::webauthn {

namespace {

// Common parameters (RFC 9052 section 7.1).
constexpr std::int64_t kKty = 1;
constexpr std::int64_t kAlg = 3;
constexpr std::int64_t kKeyOps = 4;
constexpr std::int64_t kKeyOpVerify = 2;

// Key types (RFC 9053 section 7, RFC 8230 section 4).
constexpr std::int64_t kOkp = 1;
constexpr std::int64_t kEc2 = 2;
constexpr std::int64_t kRsa = 3;

// EC2 and OKP parameters (RFC 9053 sections 7.1 and 7.2).
constexpr std::int64_t kCrv = -1;
constexpr std::int64_t kX = -2;
constexpr std::int64_t kY = -3;
constexpr std::int64_t kD = -4;
constexpr std::int64_t kP256 = 1;
constexpr std::int64_t kEd25519 = 6;

// RSA parameters (RFC 8230 section 4): n and e; -3 to -12 are private.
constexpr std::int64_t kN = -1;
constexpr std::int64_t kE = -2;
constexpr std::int64_t kFirstPrivateRsa = -3;
constexpr std::int64_t kLastPrivateRsa = -12;

std::span<const unsigned char> bytes_of(const cbor::Value& value) { return {reinterpret_cast<const unsigned char*>(value.string.data()), value.string.size()}; }

const cbor::Value* bytes(const cbor::Value& cose, std::int64_t label) {
  const auto* found = cose.find(label);
  return found && found->is_bytes() ? found : nullptr;
}

const cbor::Value* integer(const cbor::Value& cose, std::int64_t label) {
  const auto* found = cose.find(label);
  return found && found->is_integer() ? found : nullptr;
}

}  // namespace

std::int64_t PublicKey::algorithm() const {
  switch (kind) {
    case Kind::es256:
      return kEs256;
    case Kind::eddsa:
      return kEdDsa;
    case Kind::rs256:
      return kRs256;
  }
  return 0;
}

std::optional<PublicKey> public_key(const cbor::Value& cose) {
  if (!cose.is_map()) return std::nullopt;
  const auto* kty = integer(cose, kKty);
  const auto* alg = integer(cose, kAlg);
  if (!kty || !alg) return std::nullopt;

  // A key_ops, when present, must allow verifying.
  if (const auto* ops = cose.find(kKeyOps)) {
    if (ops->kind != cbor::Value::Kind::array) return std::nullopt;
    bool verify = false;
    for (const auto& op : ops->items) verify = verify || (op.is_integer() && op.integer == kKeyOpVerify);
    if (!verify) return std::nullopt;
  }

  PublicKey out;
  if (kty->integer == kEc2 || kty->integer == kOkp) {
    if (cose.find(kD)) return std::nullopt;
    const auto* crv = integer(cose, kCrv);
    const auto* x = bytes(cose, kX);
    if (!crv || !x) return std::nullopt;
    std::optional<Bytes> der;
    if (kty->integer == kEc2 && alg->integer == kEs256 && crv->integer == kP256) {
      const auto* y = bytes(cose, kY);
      if (!y) return std::nullopt;
      out.kind = PublicKey::Kind::es256;
      der = client::public_key_der(client::SigningAlgorithm::es256, bytes_of(*x), bytes_of(*y));
    } else if (kty->integer == kOkp && alg->integer == kEdDsa && crv->integer == kEd25519) {
      if (cose.find(kY)) return std::nullopt;
      out.kind = PublicKey::Kind::eddsa;
      der = client::public_key_der(client::SigningAlgorithm::ed25519, bytes_of(*x), {});
    }
    if (!der) return std::nullopt;
    out.der = std::move(*der);
    return out;
  }

  if (kty->integer == kRsa && alg->integer == kRs256) {
    for (std::int64_t label = kFirstPrivateRsa; label >= kLastPrivateRsa; --label)
      if (cose.find(label)) return std::nullopt;
    const auto* n = bytes(cose, kN);
    const auto* e = bytes(cose, kE);
    if (!n || !e || n->string.empty() || e->string.empty()) return std::nullopt;
    out.kind = PublicKey::Kind::rs256;
    out.modulus = n->string;
    out.exponent = e->string;
    return out;
  }

  return std::nullopt;
}

}  // namespace lugh::webauthn

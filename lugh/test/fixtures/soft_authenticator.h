//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <boost/json.hpp>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/identity/crypto.h"
#include "dannan/identity/signing.h"
#include "lugh/core/encoding.h"

// A software authenticator, written from WebAuthn Level 3 (sections 6.1, 6.5, 8.7) and RFC 8949
// and 9052 independently of lugh/webauthn, for the ceremony tests and the process tests: a key
// of its own (ES256 or EdDSA), a credential id, a sign count, and the bytes a browser would
// hand Lugh. Each part can be bent, so every check Lugh makes can be shown refusing.
namespace soft_authenticator {

using Bytes = std::vector<std::uint8_t>;

// Enough CBOR writing for an attestation object and a COSE key.
inline void head(Bytes& out, std::uint8_t major, std::uint64_t n) {
  const auto initial = static_cast<std::uint8_t>(major << 5);
  if (n < 24) {
    out.push_back(static_cast<std::uint8_t>(initial | n));
  } else if (n <= 0xff) {
    out.push_back(initial | 24);
    out.push_back(static_cast<std::uint8_t>(n));
  } else {
    out.push_back(initial | 25);
    out.push_back(static_cast<std::uint8_t>(n >> 8));
    out.push_back(static_cast<std::uint8_t>(n & 0xff));
  }
}
inline void integer(Bytes& out, std::int64_t n) { n >= 0 ? head(out, 0, static_cast<std::uint64_t>(n)) : head(out, 1, static_cast<std::uint64_t>(-1 - n)); }
inline void bytes(Bytes& out, const Bytes& value) {
  head(out, 2, value.size());
  out.insert(out.end(), value.begin(), value.end());
}
inline void text(Bytes& out, std::string_view value) {
  head(out, 3, value.size());
  out.insert(out.end(), value.begin(), value.end());
}

// What a browser returns from create() and get().
struct Created {
  Bytes client_data_json;
  Bytes attestation_object;
};
struct Signed {
  Bytes client_data_json;
  Bytes authenticator_data;
  Bytes signature;
};

class Authenticator {
 public:
  explicit Authenticator(dannan::identity::SigningAlgorithm algorithm = dannan::identity::SigningAlgorithm::es256)
      : _key(dannan::identity::SigningKey::generate(algorithm)), _credential_id(dannan::identity::random_bytes(16)) {}

  // What the ceremony carries; each defaults to what a well-behaved authenticator sends.
  std::string rp_id = "localhost";
  std::string origin = "https://localhost";
  std::string type_override;
  bool user_present = true;
  bool user_verified = true;
  bool backup_eligible = false;
  bool backed_up = false;
  bool cross_origin = false;
  std::uint32_t sign_count = 0;
  // Added to sign_count before each assertion; 0 for an authenticator that keeps none.
  std::uint32_t count_step = 1;
  std::array<std::uint8_t, 16> aaguid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

  const Bytes& credential_id() const { return _credential_id; }
  const dannan::identity::SigningKey& key() const { return _key; }

  Created create(const std::string& challenge) const {
    Created out;
    out.client_data_json = client_data(type_override.empty() ? "webauthn.create" : type_override, challenge);
    auto data = authenticator_data(sign_count, true);
    // attestationObject: {"fmt": "none", "attStmt": {}, "authData": ...}, keys in CTAP2 order.
    head(out.attestation_object, 5, 3);
    text(out.attestation_object, "fmt");
    text(out.attestation_object, "none");
    text(out.attestation_object, "attStmt");
    head(out.attestation_object, 5, 0);
    text(out.attestation_object, "authData");
    bytes(out.attestation_object, data);
    return out;
  }

  Signed get(const std::string& challenge) {
    Signed out;
    sign_count += count_step;
    out.client_data_json = client_data(type_override.empty() ? "webauthn.get" : type_override, challenge);
    out.authenticator_data = authenticator_data(sign_count, false);
    const auto hash = dannan::identity::sha256(out.client_data_json);
    Bytes message = out.authenticator_data;
    message.insert(message.end(), hash.bytes.begin(), hash.bytes.end());
    const auto raw = _key.sign(message);
    out.signature = _key.algorithm() == dannan::identity::SigningAlgorithm::es256 ? der_signature(raw) : Bytes(raw.begin(), raw.end());
    return out;
  }

  // The COSE key (RFC 9052 section 7) of this authenticator's public key.
  Bytes cose_key() const {
    const auto der = _key.public_key();
    Bytes out;
    if (_key.algorithm() == dannan::identity::SigningAlgorithm::es256) {
      head(out, 5, 5);
      integer(out, 1);
      integer(out, 2);
      integer(out, 3);
      integer(out, -7);
      integer(out, -1);
      integer(out, 1);
      integer(out, -2);
      bytes(out, Bytes(der.end() - 64, der.end() - 32));
      integer(out, -3);
      bytes(out, Bytes(der.end() - 32, der.end()));
    } else {
      head(out, 5, 4);
      integer(out, 1);
      integer(out, 1);
      integer(out, 3);
      integer(out, -8);
      integer(out, -1);
      integer(out, 6);
      integer(out, -2);
      bytes(out, Bytes(der.end() - 32, der.end()));
    }
    return out;
  }

 private:
  Bytes client_data(std::string_view type, const std::string& challenge) const {
    boost::json::object object;
    object["type"] = type;
    object["challenge"] = lugh::encoding::base64url({reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size()});
    object["origin"] = origin;
    object["crossOrigin"] = cross_origin;
    const auto json = boost::json::serialize(object);
    return Bytes(json.begin(), json.end());
  }

  Bytes authenticator_data(std::uint32_t count, bool attested) const {
    const auto rp = dannan::identity::sha256({reinterpret_cast<const std::uint8_t*>(rp_id.data()), rp_id.size()});
    Bytes out(rp.bytes.begin(), rp.bytes.end());
    std::uint8_t flags = 0;
    if (user_present) flags |= 0x01;
    if (user_verified) flags |= 0x04;
    if (backup_eligible) flags |= 0x08;
    if (backed_up) flags |= 0x10;
    if (attested) flags |= 0x40;
    out.push_back(flags);
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(count >> shift));
    if (attested) {
      out.insert(out.end(), aaguid.begin(), aaguid.end());
      out.push_back(static_cast<std::uint8_t>(_credential_id.size() >> 8));
      out.push_back(static_cast<std::uint8_t>(_credential_id.size() & 0xff));
      out.insert(out.end(), _credential_id.begin(), _credential_id.end());
      const auto cose = cose_key();
      out.insert(out.end(), cose.begin(), cose.end());
    }
    return out;
  }

  // ECDSA-Sig-Value (RFC 3279): SEQUENCE of two minimal positive INTEGERs.
  static Bytes der_signature(const Bytes& raw) {
    const auto integer_of = [](const std::uint8_t* at) {
      Bytes value(at, at + 32);
      while (value.size() > 1 && value[0] == 0 && !(value[1] & 0x80)) value.erase(value.begin());
      if (value[0] & 0x80) value.insert(value.begin(), 0x00);
      Bytes out{0x02, static_cast<std::uint8_t>(value.size())};
      out.insert(out.end(), value.begin(), value.end());
      return out;
    };
    const auto r = integer_of(raw.data());
    const auto s = integer_of(raw.data() + 32);
    Bytes out{0x30, static_cast<std::uint8_t>(r.size() + s.size())};
    out.insert(out.end(), r.begin(), r.end());
    out.insert(out.end(), s.begin(), s.end());
    return out;
  }

  dannan::identity::SigningKey _key;
  Bytes _credential_id;
};

}  // namespace soft_authenticator

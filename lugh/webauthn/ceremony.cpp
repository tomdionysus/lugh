//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/webauthn/ceremony.h"

#include <algorithm>
#include <boost/json.hpp>

#include "dannan/identity/crypto.h"
#include "dannan/identity/signing.h"
#include "lugh/core/encoding.h"

namespace lugh::webauthn {

namespace {

constexpr std::size_t kMostClientDataBytes = 4096;
constexpr std::size_t kMostCredentialIdBytes = 1023;

std::span<const std::uint8_t> bytes_of(std::string_view text) { return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()}; }

template <typename T>
Outcome<T> refused(std::string why) {
  return Outcome<T>::failure(Fault::refused, std::move(why));
}

struct ClientData {
  std::string type;
  std::string challenge;
  std::string origin;
};

// Section 5.8.1: a JSON object with type, challenge (base64url) and origin; crossOrigin, when
// present, false. A topOrigin means a ceremony inside another site's frame, which Lugh does
// not allow.
std::optional<ClientData> parse_client_data(std::span<const std::uint8_t> json) {
  if (json.empty() || json.size() > kMostClientDataBytes) return std::nullopt;
  boost::system::error_code ec;
  const auto parsed = boost::json::parse(std::string_view(reinterpret_cast<const char*>(json.data()), json.size()), ec);
  if (ec || !parsed.is_object()) return std::nullopt;
  const auto& object = parsed.as_object();
  const auto text = [&](std::string_view name) -> std::optional<std::string> {
    const auto* found = object.if_contains(name);
    if (!found || !found->is_string()) return std::nullopt;
    return std::string(found->as_string());
  };
  ClientData out;
  const auto type = text("type");
  const auto challenge = text("challenge");
  const auto origin = text("origin");
  if (!type || !challenge || !origin) return std::nullopt;
  const auto raw = encoding::base64url_decode(*challenge);
  if (!raw) return std::nullopt;
  if (const auto* cross = object.if_contains("crossOrigin"); cross && !(cross->is_bool() && !cross->as_bool())) return std::nullopt;
  if (object.contains("topOrigin")) return std::nullopt;
  out.type = *type;
  out.challenge.assign(raw->begin(), raw->end());
  out.origin = *origin;
  return out;
}

// The checks sections 7.1 and 7.2 share: the client data's type, challenge and origin, and the
// authenticator data's RP ID hash and flags.
Outcome<> common(const Expected& expected, const ClientData& client, const AuthenticatorData& data, std::string_view type) {
  if (client.type != type) return refused<Nothing>("the client data is not a " + std::string(type));
  if (expected.challenge.empty() || !dannan::identity::constant_time_equal(bytes_of(client.challenge), bytes_of(expected.challenge)))
    return refused<Nothing>("the challenge is not the one issued");
  if (std::find(expected.origins.begin(), expected.origins.end(), client.origin) == expected.origins.end())
    return refused<Nothing>("the ceremony came from another origin");
  const auto rp = dannan::identity::sha256(bytes_of(expected.rp_id));
  if (!std::equal(rp.bytes.begin(), rp.bytes.end(), data.rp_id_hash.begin())) return refused<Nothing>("the authenticator signed for another RP ID");
  if (!data.user_present()) return refused<Nothing>("the user was not present");
  if (expected.user_verification && !data.user_verified()) return refused<Nothing>("the user was not verified");
  return Outcome<>::success();
}

std::uint32_t big_endian32(std::span<const std::uint8_t> bytes) {
  return (std::uint32_t{bytes[0]} << 24) | (std::uint32_t{bytes[1]} << 16) | (std::uint32_t{bytes[2]} << 8) | bytes[3];
}

// One DER INTEGER, positive and minimal, as at most 32 bytes right-aligned in `out`.
bool der_integer(std::span<const std::uint8_t>& in, std::span<std::uint8_t, 32> out) {
  if (in.size() < 2 || in[0] != 0x02) return false;
  const std::size_t length = in[1];
  if (length == 0 || length > 33 || in.size() < 2 + length) return false;
  auto value = in.subspan(2, length);
  if (value[0] & 0x80) return false;
  if (value[0] == 0x00) {
    // A leading zero only where the next byte would read as negative.
    if (length == 1 || !(value[1] & 0x80)) return false;
    value = value.subspan(1);
  }
  if (value.size() > 32) return false;
  std::fill(out.begin(), out.end(), 0);
  std::copy(value.begin(), value.end(), out.begin() + static_cast<std::ptrdiff_t>(32 - value.size()));
  in = in.subspan(2 + length);
  return true;
}

bool verify(const PublicKey& key, std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) {
  switch (key.kind) {
    case PublicKey::Kind::es256: {
      const auto raw = es256_raw_signature(signature);
      return raw && dannan::identity::verify(dannan::identity::SigningAlgorithm::es256, key.der, message, *raw);
    }
    case PublicKey::Kind::eddsa:
      return dannan::identity::verify(dannan::identity::SigningAlgorithm::ed25519, key.der, message, signature);
    case PublicKey::Kind::rs256:
      return dannan::identity::verify_rs256(bytes_of(key.modulus), bytes_of(key.exponent), message, signature);
  }
  return false;
}

}  // namespace

std::optional<std::array<std::uint8_t, 64>> es256_raw_signature(std::span<const std::uint8_t> der) {
  // SEQUENCE, short-form length (two INTEGERs of at most 33 bytes fit in under 128).
  if (der.size() < 8 || der[0] != 0x30 || der[1] != der.size() - 2) return std::nullopt;
  std::array<std::uint8_t, 64> out{};
  auto rest = der.subspan(2);
  if (!der_integer(rest, std::span<std::uint8_t, 32>(out.data(), 32))) return std::nullopt;
  if (!der_integer(rest, std::span<std::uint8_t, 32>(out.data() + 32, 32))) return std::nullopt;
  if (!rest.empty()) return std::nullopt;
  return out;
}

std::optional<AuthenticatorData> parse_authenticator_data(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < 37) return std::nullopt;
  AuthenticatorData out;
  std::copy(bytes.begin(), bytes.begin() + 32, out.rp_id_hash.begin());
  out.flags = bytes[32];
  out.sign_count = big_endian32(bytes.subspan(33, 4));
  if (out.backed_up() && !out.backup_eligible()) return std::nullopt;
  auto rest = bytes.subspan(37);

  if (out.flags & kAttestedData) {
    if (rest.size() < 18) return std::nullopt;
    AttestedCredential credential;
    std::copy(rest.begin(), rest.begin() + 16, credential.aaguid.begin());
    const std::size_t length = (std::size_t{rest[16]} << 8) | rest[17];
    rest = rest.subspan(18);
    if (length == 0 || length > kMostCredentialIdBytes || rest.size() < length) return std::nullopt;
    credential.credential_id.assign(reinterpret_cast<const char*>(rest.data()), length);
    rest = rest.subspan(length);
    std::size_t used = 0;
    const auto cose = cbor::decode(rest, &used);
    if (!cose) return std::nullopt;
    const auto key = public_key(*cose);
    if (!key) return std::nullopt;
    credential.key = *key;
    rest = rest.subspan(used);
    out.credential = std::move(credential);
  }

  if (out.flags & kExtensionData) {
    const auto extensions = cbor::decode(rest);
    if (!extensions || !extensions->is_map()) return std::nullopt;
    rest = {};
  }
  if (!rest.empty()) return std::nullopt;
  return out;
}

Outcome<Registered> check_registration(const Expected& expected, std::span<const std::uint8_t> client_data_json,
                                       std::span<const std::uint8_t> attestation_object) {
  const auto client = parse_client_data(client_data_json);
  if (!client) return refused<Registered>("the client data is not well formed");

  // The attestation object: fmt (text), attStmt (a map) and authData (bytes). The statement is
  // not judged: attestation is `none`.
  const auto object = cbor::decode(attestation_object);
  if (!object || !object->is_map()) return refused<Registered>("the attestation object is not well formed");
  const auto* fmt = object->find("fmt");
  const auto* statement = object->find("attStmt");
  const auto* auth_data = object->find("authData");
  if (!fmt || !fmt->is_text() || !statement || !statement->is_map() || !auth_data || !auth_data->is_bytes())
    return refused<Registered>("the attestation object is not well formed");
  const auto data = parse_authenticator_data(bytes_of(auth_data->string));
  if (!data) return refused<Registered>("the authenticator data is not well formed");

  if (const auto ok = common(expected, *client, *data, "webauthn.create"); !ok.ok()) return Outcome<Registered>::from(ok);
  if (!data->credential) return refused<Registered>("the authenticator made no credential");

  Registered out;
  out.credential = *data->credential;
  out.sign_count = data->sign_count;
  out.user_verified = data->user_verified();
  out.backup_eligible = data->backup_eligible();
  out.backed_up = data->backed_up();
  return Outcome<Registered>::success(std::move(out));
}

Outcome<Asserted> check_assertion(const Expected& expected, const Credential& credential, std::span<const std::uint8_t> client_data_json,
                                  std::span<const std::uint8_t> authenticator_data, std::span<const std::uint8_t> signature) {
  const auto client = parse_client_data(client_data_json);
  if (!client) return refused<Asserted>("the client data is not well formed");
  const auto data = parse_authenticator_data(authenticator_data);
  if (!data) return refused<Asserted>("the authenticator data is not well formed");
  if (data->credential) return refused<Asserted>("an assertion carries no new credential");

  if (const auto ok = common(expected, *client, *data, "webauthn.get"); !ok.ok()) return Outcome<Asserted>::from(ok);
  if (data->backup_eligible() != credential.backup_eligible) return refused<Asserted>("the authenticator's backup eligibility changed");

  // The signature is over the authenticator data and the hash of the client data (7.2, 20).
  const auto client_hash = dannan::identity::sha256(client_data_json);
  std::vector<std::uint8_t> signed_bytes(authenticator_data.begin(), authenticator_data.end());
  signed_bytes.insert(signed_bytes.end(), client_hash.bytes.begin(), client_hash.bytes.end());
  if (!verify(credential.key, signed_bytes, signature)) return refused<Asserted>("the signature does not verify");

  // 7.2, 22: a count that does not move forward is a cloned authenticator, unless both are 0.
  if ((data->sign_count != 0 || credential.sign_count != 0) && data->sign_count <= credential.sign_count)
    return refused<Asserted>("the sign count did not move forward: the authenticator may be cloned");

  Asserted out;
  out.sign_count = data->sign_count;
  out.user_verified = data->user_verified();
  out.backed_up = data->backed_up();
  return Outcome<Asserted>::success(out);
}

}  // namespace lugh::webauthn

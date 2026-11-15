//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "lugh/core/outcome.h"
#include "lugh/webauthn/cose.h"

// The relying party's checks of a WebAuthn ceremony (W3C Web Authentication Level 3, sections
// 7.1 and 7.2), with no network and no store: what the browser sent, judged against what
// Lugh expected. TODO/2026-11-15-p11-webauthn.md, W2.
//
// - Attestation is `none` (the maintainer, 2026-11-15). Any attestation statement is ignored, whatever
//   its format, and the AAGUID is kept as the authenticator's claim, unverified.
// - Each refusal is Fault::refused with a message naming the check, never a value read.
// - RS256 credentials are registered now. Their assertions are verified once Dannan's
//   verify_rs256 is pinned; until then an RS256 assertion is refused as not yet verifiable.
namespace lugh::webauthn {

// Authenticator data flags (section 6.1).
inline constexpr std::uint8_t kUserPresent = 0x01;
inline constexpr std::uint8_t kUserVerified = 0x04;
inline constexpr std::uint8_t kBackupEligible = 0x08;
inline constexpr std::uint8_t kBackedUp = 0x10;
inline constexpr std::uint8_t kAttestedData = 0x40;
inline constexpr std::uint8_t kExtensionData = 0x80;

// What Lugh expects of a ceremony it began.
struct Expected {
  // The RP ID: the issuer's host. Its SHA-256 must be the authenticator data's first 32 bytes.
  std::string rp_id;
  // The origins a ceremony may come from ("https://id.example.com"), exactly.
  std::vector<std::string> origins;
  // The challenge Lugh issued, as raw bytes.
  std::string challenge;
  // Whether the user must have been verified (a PIN or biometric): for a passkey that signs in
  // alone, and when policy asks for it.
  bool user_verification = false;
};

struct AttestedCredential {
  std::array<std::uint8_t, 16> aaguid{};
  std::string credential_id;
  PublicKey key;
};

// Authenticator data (section 6.1), parsed strictly: the attested-data flag set exactly when
// attested credential data follows; the extension flag set exactly when an extension map
// follows; nothing after; backed up never without backup-eligible.
struct AuthenticatorData {
  std::array<std::uint8_t, 32> rp_id_hash{};
  std::uint8_t flags = 0;
  std::uint32_t sign_count = 0;
  std::optional<AttestedCredential> credential;

  bool user_present() const { return flags & kUserPresent; }
  bool user_verified() const { return flags & kUserVerified; }
  bool backup_eligible() const { return flags & kBackupEligible; }
  bool backed_up() const { return flags & kBackedUp; }
};

std::optional<AuthenticatorData> parse_authenticator_data(std::span<const std::uint8_t> bytes);

// What a registration gives Lugh to store.
struct Registered {
  AttestedCredential credential;
  std::uint32_t sign_count = 0;
  bool user_verified = false;
  bool backup_eligible = false;
  bool backed_up = false;
};

// Section 7.1: `client_data_json` and `attestation_object` as the browser returned them.
Outcome<Registered> check_registration(const Expected& expected, std::span<const std::uint8_t> client_data_json,
                                       std::span<const std::uint8_t> attestation_object);

// A credential as Lugh holds it, for an assertion.
struct Credential {
  std::string credential_id;
  PublicKey key;
  std::uint32_t sign_count = 0;
  // As registered: an authenticator's backup eligibility never changes (section 6.1.3).
  bool backup_eligible = false;
};

// What an assertion proves.
struct Asserted {
  std::uint32_t sign_count = 0;
  bool user_verified = false;
  bool backed_up = false;
};

// Section 7.2: the assertion's parts as the browser returned them, against the credential its
// id named. A sign count that does not move forward is refused (a cloned authenticator),
// except while both counts are 0 (an authenticator that keeps none).
Outcome<Asserted> check_assertion(const Expected& expected, const Credential& credential, std::span<const std::uint8_t> client_data_json,
                                  std::span<const std::uint8_t> authenticator_data, std::span<const std::uint8_t> signature);

// ES256's signature as WebAuthn carries it (an ASN.1 DER ECDSA-Sig-Value) as the 64 raw bytes
// Dannan verifies (r then s); nothing for anything but the strict DER of two positive
// integers of at most 32 bytes.
std::optional<std::array<std::uint8_t, 64>> es256_raw_signature(std::span<const std::uint8_t> der);

}  // namespace lugh::webauthn

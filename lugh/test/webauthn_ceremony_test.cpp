//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/soft_authenticator.h"
#include "lugh/webauthn/ceremony.h"

using namespace lugh::webauthn;
using soft_authenticator::Authenticator;
using SigningAlgorithm = dannan::identity::SigningAlgorithm;

namespace {

const std::string kChallenge = "a challenge of 32 bytes, random!";

Expected expected(bool user_verification = true) {
  Expected out;
  out.rp_id = "localhost";
  out.origins = {"https://localhost"};
  out.challenge = kChallenge;
  out.user_verification = user_verification;
  return out;
}

lugh::Outcome<Registered> registered(const Authenticator& authenticator, const Expected& wanted = expected()) {
  const auto made = authenticator.create(kChallenge);
  return check_registration(wanted, made.client_data_json, made.attestation_object);
}

Credential credential_of(const Registered& made) { return {made.credential.credential_id, made.credential.key, made.sign_count, made.backup_eligible}; }

lugh::Outcome<Asserted> asserted(Authenticator& authenticator, const Credential& credential, const Expected& wanted = expected()) {
  const auto proof = authenticator.get(kChallenge);
  return check_assertion(wanted, credential, proof.client_data_json, proof.authenticator_data, proof.signature);
}

}  // namespace

TEST(WebAuthn, RegistersThenAssertsWithEs256) {
  Authenticator authenticator;
  const auto made = registered(authenticator);
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.credential.key.kind, PublicKey::Kind::es256);
  EXPECT_EQ(made.value.credential.credential_id, std::string(authenticator.credential_id().begin(), authenticator.credential_id().end()));
  EXPECT_EQ(made.value.credential.aaguid, authenticator.aaguid);
  EXPECT_TRUE(made.value.user_verified);

  const auto proof = asserted(authenticator, credential_of(made.value));
  ASSERT_TRUE(proof.ok()) << proof.message;
  EXPECT_EQ(proof.value.sign_count, 1u);
  EXPECT_TRUE(proof.value.user_verified);
}

TEST(WebAuthn, RegistersThenAssertsWithEdDsa) {
  Authenticator authenticator(SigningAlgorithm::ed25519);
  const auto made = registered(authenticator);
  ASSERT_TRUE(made.ok()) << made.message;
  EXPECT_EQ(made.value.credential.key.kind, PublicKey::Kind::eddsa);
  EXPECT_TRUE(asserted(authenticator, credential_of(made.value)).ok());
}

// Section 7.1, steps 7 to 14 and 7.2, steps 11 to 17: each refuses alone.
TEST(WebAuthn, TheClientDataIsChecked) {
  Authenticator wrong_type;
  wrong_type.type_override = "webauthn.get";
  EXPECT_FALSE(registered(wrong_type).ok()) << "a get presented as a create";

  Authenticator elsewhere;
  elsewhere.origin = "https://localhost.evil.example";
  EXPECT_FALSE(registered(elsewhere).ok()) << "another origin";

  Authenticator framed;
  framed.cross_origin = true;
  EXPECT_FALSE(registered(framed).ok()) << "inside another site's frame";

  Authenticator honest;
  auto other = expected();
  other.challenge = "another challenge, not the one!!";
  EXPECT_FALSE(registered(honest, other).ok()) << "another challenge";
  other.challenge.clear();
  EXPECT_FALSE(registered(honest, other).ok()) << "no challenge issued at all";
}

TEST(WebAuthn, TheAuthenticatorDataIsChecked) {
  Authenticator other_rp;
  other_rp.rp_id = "evil.example";
  EXPECT_FALSE(registered(other_rp).ok()) << "signed for another RP ID";

  Authenticator absent;
  absent.user_present = false;
  EXPECT_FALSE(registered(absent).ok()) << "no user present";

  Authenticator unverified;
  unverified.user_verified = false;
  EXPECT_FALSE(registered(unverified).ok()) << "not verified where verification is required";
  const auto second_factor = registered(unverified, expected(false));
  ASSERT_TRUE(second_factor.ok()) << "a security key without a PIN, as a second factor";
  EXPECT_FALSE(second_factor.value.user_verified);

  Authenticator inconsistent;
  inconsistent.backed_up = true;
  EXPECT_FALSE(registered(inconsistent).ok()) << "backed up but not backup-eligible";
}

TEST(WebAuthn, AnAssertionIsSignedByTheRegisteredKey) {
  Authenticator authenticator;
  const auto made = registered(authenticator);
  ASSERT_TRUE(made.ok());

  Authenticator impostor;
  impostor.sign_count = 10;
  auto credential = credential_of(made.value);
  EXPECT_FALSE(asserted(impostor, credential).ok()) << "another key's signature";

  auto proof = authenticator.get(kChallenge);
  proof.signature.back() ^= 0x01;
  EXPECT_FALSE(check_assertion(expected(), credential, proof.client_data_json, proof.authenticator_data, proof.signature).ok()) << "a bent signature";

  auto changed = authenticator.get(kChallenge);
  changed.client_data_json.back() = ' ';
  EXPECT_FALSE(check_assertion(expected(), credential, changed.client_data_json, changed.authenticator_data, changed.signature).ok())
      << "client data changed after signing";
}

TEST(WebAuthn, TheSignCountMustMoveForward) {
  Authenticator authenticator;
  const auto made = registered(authenticator);
  ASSERT_TRUE(made.ok());
  auto credential = credential_of(made.value);
  const auto first = asserted(authenticator, credential);
  ASSERT_TRUE(first.ok());
  credential.sign_count = first.value.sign_count;

  // A clone that was copied before the last use repeats a count.
  authenticator.sign_count = credential.sign_count - 1;
  EXPECT_FALSE(asserted(authenticator, credential).ok()) << "a count that repeats";
  authenticator.sign_count = 0;
  authenticator.count_step = 0;
  EXPECT_FALSE(asserted(authenticator, credential).ok()) << "a count back to 0";
}

TEST(WebAuthn, AnAuthenticatorThatKeepsNoCountIsAccepted) {
  Authenticator synced;
  synced.backup_eligible = true;
  synced.backed_up = true;
  synced.count_step = 0;
  const auto made = registered(synced);
  ASSERT_TRUE(made.ok());
  EXPECT_TRUE(made.value.backup_eligible);
  EXPECT_TRUE(made.value.backed_up);
  const auto credential = credential_of(made.value);
  EXPECT_TRUE(asserted(synced, credential).ok());
  EXPECT_TRUE(asserted(synced, credential).ok()) << "0 again, and again";

  synced.backup_eligible = false;
  synced.backed_up = false;
  EXPECT_FALSE(asserted(synced, credential).ok()) << "backup eligibility never changes";
}

TEST(WebAuthn, AnAssertionCarriesNoNewCredential) {
  Authenticator authenticator;
  const auto made = registered(authenticator);
  ASSERT_TRUE(made.ok());
  // The create()'s bytes presented as an assertion: attested data where none belongs.
  const auto created = authenticator.create(kChallenge);
  const auto object = cbor::decode(created.attestation_object);
  ASSERT_TRUE(object);
  const auto& data = object->find("authData")->string;
  const std::vector<std::uint8_t> bytes(data.begin(), data.end());
  auto proof = authenticator.get(kChallenge);
  EXPECT_FALSE(check_assertion(expected(), credential_of(made.value), proof.client_data_json, bytes, proof.signature).ok());
}

TEST(WebAuthn, AuthenticatorDataIsParsedStrictly) {
  Authenticator authenticator;
  const auto created = authenticator.create(kChallenge);
  const auto object = cbor::decode(created.attestation_object);
  ASSERT_TRUE(object);
  const auto& text = object->find("authData")->string;
  const std::vector<std::uint8_t> data(text.begin(), text.end());
  ASSERT_TRUE(parse_authenticator_data(data));

  auto trailing = data;
  trailing.push_back(0x00);
  EXPECT_FALSE(parse_authenticator_data(trailing)) << "bytes after the COSE key";

  auto no_attested_flag = data;
  no_attested_flag[32] &= static_cast<std::uint8_t>(~kAttestedData);
  EXPECT_FALSE(parse_authenticator_data(no_attested_flag)) << "attested data without its flag";

  auto extensions_flag = data;
  extensions_flag[32] |= kExtensionData;
  EXPECT_FALSE(parse_authenticator_data(extensions_flag)) << "an extension flag with no extensions";

  auto with_extensions = data;
  with_extensions[32] |= kExtensionData;
  with_extensions.push_back(0xa0);
  EXPECT_TRUE(parse_authenticator_data(with_extensions)) << "an empty extension map";

  EXPECT_FALSE(parse_authenticator_data(std::span<const std::uint8_t>(data).first(36))) << "short of the count";
  auto long_id = data;
  long_id[53] = 0xff;
  long_id[54] = 0xff;
  EXPECT_FALSE(parse_authenticator_data(long_id)) << "a credential id longer than what follows";
}

// RFC 3279's ECDSA-Sig-Value, strictly.
TEST(WebAuthn, Es256SignaturesAreStrictDer) {
  std::vector<std::uint8_t> der{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
  const auto raw = es256_raw_signature(der);
  ASSERT_TRUE(raw);
  EXPECT_EQ((*raw)[31], 0x01);
  EXPECT_EQ((*raw)[63], 0x02);
  EXPECT_EQ((*raw)[0], 0x00);

  EXPECT_FALSE(es256_raw_signature(std::vector<std::uint8_t>{0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02})) << "a negative r";
  EXPECT_FALSE(es256_raw_signature(std::vector<std::uint8_t>{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02})) << "a needless leading zero";
  EXPECT_FALSE(es256_raw_signature(std::vector<std::uint8_t>{0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00})) << "a byte after s";
  EXPECT_FALSE(es256_raw_signature(std::vector<std::uint8_t>{0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02})) << "a length that lies";
  EXPECT_FALSE(es256_raw_signature(std::vector<std::uint8_t>{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02})) << "a SET, not a SEQUENCE";
  std::vector<std::uint8_t> long_r{0x30, 0x27, 0x02, 0x22, 0x00};
  long_r.insert(long_r.end(), 33, 0x80);
  long_r.insert(long_r.end(), {0x02, 0x01, 0x01});
  EXPECT_FALSE(es256_raw_signature(long_r)) << "an r longer than 32 bytes";
}

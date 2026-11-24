//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The stored password is Dannan's (identity/password.h, 0.12.0); how a Lugh record carries it is
// Lugh's, and it must be the same bytes as before the move, so every hash already stored still
// verifies: the three costs as big-endian u32s, then the salt and the hash, each a blob (a u32 length
// and its bytes). These bytes are built by hand from that layout, not by the writer under test.

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "lugh/authn/password_hash.h"
#include "lugh/crypto/argon2.h"

namespace {

using Bytes = std::vector<unsigned char>;

void u32(Bytes& out, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<unsigned char>(value >> shift));
}

void blob(Bytes& out, std::span<const unsigned char> bytes) {
  u32(out, static_cast<std::uint32_t>(bytes.size()));
  out.insert(out.end(), bytes.begin(), bytes.end());
}

// A record's password field as Lugh wrote it before Dannan held the stored password: Argon2id of
// `password` under a fixed salt and small costs.
Bytes stored_before(const Bytes& password, const Bytes& salt) {
  const lugh::crypto::Argon2Costs costs{64, 1, 1};
  const auto hash = lugh::crypto::stretch(password, salt, costs, 32);
  EXPECT_TRUE(hash.ok) << hash.error;
  Bytes out;
  u32(out, costs.memory_kib);
  u32(out, costs.iterations);
  u32(out, costs.lanes);
  blob(out, salt);
  blob(out, std::span<const unsigned char>(hash.value.data(), hash.value.size()));
  return out;
}

const Bytes kPassword{'c', 'o', 'r', 'r', 'e', 'c', 't', ' ', 'h', 'o', 'r', 's', 'e'};

Bytes salt16() {
  Bytes salt(16);
  for (std::size_t i = 0; i < salt.size(); ++i) salt[i] = static_cast<unsigned char>(i * 7 + 3);
  return salt;
}

}  // namespace

TEST(StoredPassword, AHashStoredBeforeTheMoveStillVerifies) {
  const auto bytes = stored_before(kPassword, salt16());
  const auto read = lugh::decode_whole<lugh::authn::PasswordHash>(bytes, lugh::authn::read_password_hash);
  ASSERT_TRUE(read);
  EXPECT_TRUE(lugh::authn::verify_password(kPassword, *read));
  EXPECT_FALSE(lugh::authn::verify_password(Bytes{'w', 'r', 'o', 'n', 'g'}, *read));
}

TEST(StoredPassword, WritesTheSameBytesItReads) {
  const auto bytes = stored_before(kPassword, salt16());
  const auto read = lugh::decode_whole<lugh::authn::PasswordHash>(bytes, lugh::authn::read_password_hash);
  ASSERT_TRUE(read);
  lugh::SecureWriter writer;
  lugh::authn::write_password_hash(writer, *read);
  const auto written = writer.take();
  EXPECT_EQ(Bytes(written.begin(), written.end()), bytes);
}

TEST(StoredPassword, ANewHashVerifiesAndRoundTrips) {
  const auto made = lugh::authn::hash_password(kPassword, {64, 1, 1});
  ASSERT_TRUE(made.ok) << made.error;
  lugh::SecureWriter writer;
  lugh::authn::write_password_hash(writer, made.value);
  const auto written = writer.take();
  const auto read = lugh::decode_whole<lugh::authn::PasswordHash>(written, lugh::authn::read_password_hash);
  ASSERT_TRUE(read);
  EXPECT_EQ(*read, made.value);
  EXPECT_TRUE(lugh::authn::verify_password(kPassword, *read));
}

// Lugh only ever wrote a 16-byte salt and a 32-byte hash; anything else is not a stored password,
// and costs out of bounds are refused before any work.
TEST(StoredPassword, RefusesWhatLughNeverWrote) {
  Bytes short_salt(8, 1);
  const auto eight = stored_before(kPassword, short_salt);
  EXPECT_FALSE((lugh::decode_whole<lugh::authn::PasswordHash>(eight, lugh::authn::read_password_hash)));

  auto costly = stored_before(kPassword, salt16());
  costly[0] = 0x7f;  // memory_kib far past the bound
  EXPECT_FALSE((lugh::decode_whole<lugh::authn::PasswordHash>(costly, lugh::authn::read_password_hash)));

  EXPECT_FALSE(lugh::authn::hash_password(kPassword, {1u << 31, 1, 1}).ok) << "costs out of bounds are refused, not spent";
}

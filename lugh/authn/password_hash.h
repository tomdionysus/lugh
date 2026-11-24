//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <span>

#include "dannan/identity/password.h"
#include "lugh/core/codec.h"
#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"
#include "lugh/crypto/argon2.h"

// A stored password, a client secret, an app password or a recovery code is Dannan's stored
// password (dannan/identity/password.h, 0.12.0, moved there from here): Argon2id with the costs and
// the salt it was made with, so the costs can rise later without anyone's hash being lost, a hash
// under old costs made again at the next sign-in. What is Lugh's is how a record carries it, the
// same bytes as before, so every stored hash still verifies.
namespace lugh::authn {

using PasswordHash = dannan::identity::PasswordHash;
using dannan::identity::verify_password;

inline constexpr std::size_t kPasswordSaltBytes = dannan::identity::password_salt_bytes;
inline constexpr std::size_t kPasswordHashBytes = dannan::identity::password_hash_bytes;

// A new hash of `secret` under `params`, with a fresh salt. A failure (costs out of bounds, which
// a caller's configuration was checked against) as a Result, as before.
Result<PasswordHash> hash_password(std::span<const unsigned char> secret, const crypto::Argon2Costs& params);

inline bool same_costs(const crypto::Argon2Costs& a, const crypto::Argon2Costs& b) {
  return a.memory_kib == b.memory_kib && a.iterations == b.iterations && a.lanes == b.lanes;
}

// Within a record: the costs, then the salt and the hash, each a blob.
inline void write_password_hash(SecureWriter& writer, const PasswordHash& hash) {
  writer.u32(hash.costs.memory_kib);
  writer.u32(hash.costs.iterations);
  writer.u32(hash.costs.lanes);
  writer.bytes(hash.salt);
  writer.bytes(hash.hash);
}

// nullopt for costs out of bounds, a salt or a hash of another length (Lugh has only ever written
// 16 and 32 bytes). Throws DecodeError for bytes that run short, as every read does.
std::optional<PasswordHash> read_password_hash(dannan::net::Reader& reader);

}  // namespace lugh::authn

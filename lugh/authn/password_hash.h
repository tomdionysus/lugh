//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <span>

#include "lugh/core/codec.h"
#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"
#include "lugh/crypto/argon2.h"

namespace lugh::authn {

// An Argon2id hash with the costs and salt it was made with, so the costs can rise later
// without anyone's hash being lost: a hash under old costs is made again at the next
// sign-in.
struct PasswordHash {
  crypto::Argon2Costs params;
  Bytes salt;
  SecureBuffer hash;
};

inline constexpr std::size_t kPasswordSaltBytes = 16;
inline constexpr std::size_t kPasswordHashBytes = 32;

// A new hash of `secret` under `params`, with a fresh salt.
Result<PasswordHash> hash_password(std::span<const unsigned char> secret, const crypto::Argon2Costs& params);

// Constant time over the hash. False for a hash whose costs are out of bounds, without
// spending anything on it.
bool verify_password(std::span<const unsigned char> secret, const PasswordHash& hash);

inline bool same_costs(const crypto::Argon2Costs& a, const crypto::Argon2Costs& b) {
  return a.memory_kib == b.memory_kib && a.iterations == b.iterations && a.lanes == b.lanes;
}

// Within a record: the costs, then the salt and the hash, each a blob.
inline void write_password_hash(SecureWriter& writer, const PasswordHash& hash) {
  writer.u32(hash.params.memory_kib);
  writer.u32(hash.params.iterations);
  writer.u32(hash.params.lanes);
  writer.bytes(hash.salt);
  writer.bytes(hash.hash);
}

// nullopt for costs out of bounds, a salt too short, or a hash of the wrong length. Throws
// DecodeError for bytes that run short, as every read does.
std::optional<PasswordHash> read_password_hash(dannan::net::Reader& reader);

}  // namespace lugh::authn

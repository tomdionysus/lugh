//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/password_hash.h"

#include "dannan/identity/crypto.h"

namespace lugh::authn {

Result<PasswordHash> hash_password(std::span<const unsigned char> secret, const crypto::Argon2Costs& params, system::Random& random) {
  using Answer = Result<PasswordHash>;
  PasswordHash out;
  out.params = params;
  out.salt = random.bytes(kPasswordSaltBytes);
  if (out.salt.empty()) return Answer::failure("no randomness for a salt");

  auto hashed = crypto::stretch(secret, out.salt, params, kPasswordHashBytes);
  if (!hashed.ok) return Answer::failure(hashed.error);
  out.hash = std::move(hashed.value);
  return Answer::success(std::move(out));
}

bool verify_password(std::span<const unsigned char> secret, const PasswordHash& hash) {
  if (!crypto::bounded(hash.params) || hash.hash.size() != kPasswordHashBytes) return false;
  const auto computed = crypto::stretch(secret, hash.salt, hash.params, kPasswordHashBytes);
  return computed.ok && dannan::identity::constant_time_equal(computed.value, hash.hash);
}

std::optional<PasswordHash> read_password_hash(ByteReader& reader) {
  PasswordHash out;
  const auto memory = reader.u32();
  const auto iterations = reader.u32();
  const auto lanes = reader.u32();
  const auto salt_length = reader.u8();
  if (!memory || !iterations || !lanes || !salt_length) return std::nullopt;
  const auto salt = reader.bytes(*salt_length);
  const auto hash_length = reader.u8();
  if (!salt || !hash_length || *hash_length != kPasswordHashBytes) return std::nullopt;
  const auto hash = reader.bytes(*hash_length);
  if (!hash) return std::nullopt;

  out.params = crypto::Argon2Costs{*memory, *iterations, *lanes};
  if (!crypto::bounded(out.params) || salt->size() < crypto::kArgon2MinimumSalt) return std::nullopt;
  out.salt.assign(salt->begin(), salt->end());
  out.hash.assign(hash->begin(), hash->end());
  return out;
}

}  // namespace lugh::authn

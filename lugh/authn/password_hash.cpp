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
  if (!hash.params.valid() || hash.hash.size() != kPasswordHashBytes) return false;
  const auto computed = crypto::stretch(secret, hash.salt, hash.params, kPasswordHashBytes);
  return computed.ok && dannan::identity::constant_time_equal(computed.value, hash.hash);
}

std::optional<PasswordHash> read_password_hash(dannan::net::Reader& reader) {
  PasswordHash out;
  out.params.memory_kib = reader.u32();
  out.params.iterations = reader.u32();
  out.params.lanes = reader.u32();
  const auto salt = reader.view_bytes(kPasswordSaltBytes * 4);
  const auto hash = reader.view_bytes(kPasswordHashBytes);
  if (!out.params.valid() || salt.size() < crypto::kArgon2MinimumSalt || hash.size() != kPasswordHashBytes) return std::nullopt;
  out.salt.assign(salt.begin(), salt.end());
  out.hash.assign(hash.begin(), hash.end());
  return out;
}

}  // namespace lugh::authn

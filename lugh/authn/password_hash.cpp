//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/password_hash.h"

#include <algorithm>
#include <stdexcept>

namespace lugh::authn {

Result<PasswordHash> hash_password(std::span<const unsigned char> secret, const crypto::Argon2Costs& params) {
  try {
    return Result<PasswordHash>::success(dannan::identity::make_password(secret, params));
  } catch (const std::exception& e) {
    return Result<PasswordHash>::failure(std::string("no password hash: ") + e.what());
  }
}

std::optional<PasswordHash> read_password_hash(dannan::net::Reader& reader) {
  PasswordHash out;
  out.costs.memory_kib = reader.u32();
  out.costs.iterations = reader.u32();
  out.costs.lanes = reader.u32();
  const auto salt = reader.view_bytes(kPasswordSaltBytes * 4);
  const auto hash = reader.view_bytes(kPasswordHashBytes);
  if (!out.costs.valid() || salt.size() != kPasswordSaltBytes || hash.size() != kPasswordHashBytes) return std::nullopt;
  std::copy(salt.begin(), salt.end(), out.salt.begin());
  std::copy(hash.begin(), hash.end(), out.hash.begin());
  return out;
}

}  // namespace lugh::authn

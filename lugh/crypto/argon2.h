//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

#include "dannan/identity/argon2.h"
#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"

// Argon2id is Dannan's (dannan/identity/argon2.h), for the whole stack, and so is the
// ceiling on what costs a record may ask for (Argon2Costs::valid()). What is here is the
// stretch into a growable secure buffer, with a failure as a Result.
namespace lugh::crypto {

using Argon2Costs = dannan::identity::Argon2Costs;

inline constexpr std::size_t kArgon2MinimumSalt = 8;
// Argon2id's tag, `length` bytes, into SecureBuffer; a failure as a Result.
inline Result<SecureBuffer> stretch(std::span<const unsigned char> password, std::span<const unsigned char> salt, const Argon2Costs& costs,
                                    std::size_t length) {
  try {
    const auto tag = dannan::identity::argon2id(password, salt, costs, length);
    return Result<SecureBuffer>::success(SecureBuffer(tag.reveal().begin(), tag.reveal().end()));
  } catch (const std::exception& e) {
    return Result<SecureBuffer>::failure(std::string("Argon2id: ") + e.what());
  }
}

}  // namespace lugh::crypto

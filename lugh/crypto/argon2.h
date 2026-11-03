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

// Argon2id is Dannan's (dannan/identity/argon2.h), for the whole stack. What is here is
// Lugh's use of it: the ceiling on costs read from a record before anything is spent on
// them, until Dannan's costs carry one (asked for), and the stretch into Lugh's own secure
// buffer, until Dannan's secure memory can grow (asked for).
namespace lugh::crypto {

using Argon2Costs = dannan::identity::Argon2Costs;

inline constexpr std::size_t kArgon2MinimumSalt = 8;
inline constexpr std::uint32_t kArgon2MostMemoryKib = 2 * 1024 * 1024;
inline constexpr std::uint32_t kArgon2MostIterations = 64;
inline constexpr std::uint32_t kArgon2MostLanes = 64;

// Costs a stored record may ask for: within the ceiling, and what Argon2 accepts (8 KiB a
// lane at least).
inline bool bounded(const Argon2Costs& costs) {
  return costs.lanes >= 1 && costs.lanes <= kArgon2MostLanes && costs.iterations >= 1 && costs.iterations <= kArgon2MostIterations &&
         costs.memory_kib >= 8 * costs.lanes && costs.memory_kib <= kArgon2MostMemoryKib;
}

// Argon2id's tag, `length` bytes, into SecureBytes; a failure as a Result.
inline Result<SecureBytes> stretch(std::span<const unsigned char> password, std::span<const unsigned char> salt, const Argon2Costs& costs, std::size_t length) {
  try {
    const auto tag = dannan::identity::argon2id(password, salt, costs, length);
    return Result<SecureBytes>::success(SecureBytes(tag.reveal().begin(), tag.reveal().end()));
  } catch (const std::exception& e) {
    return Result<SecureBytes>::failure(std::string("Argon2id: ") + e.what());
  }
}

}  // namespace lugh::crypto

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "core/secure_bytes.h"
#include "core/status.h"

namespace lugh::crypto {

// Argon2id's costs. The defaults are RFC 9106's second recommendation (64 MiB, three
// passes, four lanes), which a node can afford per sign-in and an attacker cannot per guess.
struct Argon2Params {
  std::uint32_t memory_kib = 64 * 1024;
  std::uint32_t iterations = 3;
  std::uint32_t lanes = 4;

  // The bounds a stored set of costs must fall in before anything is spent on it, so a
  // crafted header cannot ask for a terabyte. Argon2 itself needs 8 KiB per lane.
  static constexpr std::uint32_t kMostMemoryKib = 2 * 1024 * 1024;
  static constexpr std::uint32_t kMostIterations = 64;
  static constexpr std::uint32_t kMostLanes = 64;

  bool valid() const {
    return lanes >= 1 && lanes <= kMostLanes && iterations >= 1 && iterations <= kMostIterations && memory_kib >= 8 * lanes && memory_kib <= kMostMemoryKib;
  }
};

inline constexpr std::size_t kArgon2MinimumSalt = 8;

// Argon2id (RFC 9106), version 0x13, from OpenSSL 3.2. The secret (a pepper) and the
// associated data are optional, as the RFC has them.
Result<SecureBytes> argon2id(const Argon2Params& params, std::span<const unsigned char> password, std::span<const unsigned char> salt, std::size_t length,
                             std::span<const unsigned char> secret = {}, std::span<const unsigned char> associated = {});

}  // namespace lugh::crypto

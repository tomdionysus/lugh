#pragma once

#include <array>
#include <span>

namespace lugh::crypto {

inline constexpr std::size_t kSha256Bytes = 32;

// SHA-256, for checksums and hash chains. Not for passwords (Argon2id) and not for keys
// (HKDF).
std::array<unsigned char, kSha256Bytes> sha256(std::span<const unsigned char> data);

}  // namespace lugh::crypto

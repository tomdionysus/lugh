//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <span>

namespace lugh::crypto {

inline constexpr std::size_t kSha256Bytes = 32;

// SHA-256, for checksums and hash chains. Not for passwords (Argon2id) and not for keys
// (HKDF).
std::array<unsigned char, kSha256Bytes> sha256(std::span<const unsigned char> data);

}  // namespace lugh::crypto

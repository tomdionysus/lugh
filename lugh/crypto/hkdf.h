//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"

namespace lugh::crypto {

// HKDF with SHA-256 (RFC 5869), for one key from another: the master key's KEK, and
// whatever later wants a key of its own derived rather than stored. The info names the use,
// so two uses of one key never derive the same bytes.
Result<SecureBytes> hkdf_sha256(std::span<const unsigned char> key, std::span<const unsigned char> salt, std::span<const unsigned char> info,
                                std::size_t length);

}  // namespace lugh::crypto

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <span>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"

namespace lugh::crypto {

enum class HmacDigest { sha1, sha256 };

// HMAC (RFC 2104). SHA-1 is here for TOTP alone, which every authenticator app computes
// with it, and where HMAC-SHA-1 is still sound; nothing else should ask for it.
Result<Bytes> hmac(HmacDigest digest, std::span<const unsigned char> key, std::span<const unsigned char> data);

}  // namespace lugh::crypto

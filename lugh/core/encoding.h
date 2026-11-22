//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

#include "dannan/encoding/base.h"
#include "lugh/core/secure_bytes.h"

// Text forms of bytes are the stack's, Dannan's (encoding/base.h, taken from this file): every
// decoder exact, so one value has one spelling. Lugh keeps its names, and says where each decode
// lands: a TOTP secret, and any other secret, straight into a SecureBuffer, never through Bytes.
namespace lugh::encoding {

using dannan::encoding::base32;
using dannan::encoding::base64;
using dannan::encoding::base64url;
using dannan::encoding::hex;
using dannan::encoding::utf8_length;
using dannan::encoding::valid_utf8;

// RFC 4648 base32, either case, unpadded, into secure memory: what it decodes is a TOTP key.
inline std::optional<SecureBuffer> base32_decode(std::string_view text) { return dannan::encoding::base32_decode<SecureBuffer>(text); }

// RFC 4648 base64url, unpadded and exact.
inline std::optional<Bytes> base64url_decode(std::string_view text) { return dannan::encoding::base64url_decode<Bytes>(text); }

// The same, into secure memory, for a token's secret part.
inline std::optional<SecureBuffer> base64url_decode_secret(std::string_view text) { return dannan::encoding::base64url_decode<SecureBuffer>(text); }

// RFC 4648 base64 with padding, the standard alphabet (HTTP Basic, RFC 7617), exact.
inline std::optional<Bytes> base64_decode(std::string_view text) { return dannan::encoding::base64_decode<Bytes>(text); }

// Printable text within `most` bytes: valid UTF-8 with no control character (C0, DEL or C1).
// What a name, a topic level or a label may hold.
inline bool printable(std::string_view text, std::size_t most) { return text.size() <= most && dannan::encoding::printable(text); }

}  // namespace lugh::encoding

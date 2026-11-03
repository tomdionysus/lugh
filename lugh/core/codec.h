//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <optional>
#include <span>

#include "dannan/net/codec.h"
#include "lugh/core/secure_bytes.h"

// Lugh's records are written and read with Dannan's codec (dannan/net/codec.h): integers
// big-endian, a string or blob as a u32 length then its bytes. A record that holds a
// secret is written into secure memory.
namespace lugh {

using SecureWriter = dannan::net::BasicWriter<SecureBuffer>;

// The longest string field a record holds.
inline constexpr std::size_t kMostFieldBytes = 65535;

// A record decoded whole, or nothing: bytes that do not decode, or that leave something
// over, are not a record.
template <typename T, typename Read>
std::optional<T> decode_whole(std::span<const unsigned char> bytes, Read read) {
  try {
    dannan::net::Reader reader(bytes);
    std::optional<T> out = read(reader);
    if (out) reader.finish();
    return out;
  } catch (const dannan::net::DecodeError&) {
    return std::nullopt;
  }
}

}  // namespace lugh

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

#include "lugh/core/secure_bytes.h"

// Test vectors are written in hex, as the RFCs print them.
inline lugh::Bytes from_hex(std::string_view text) {
  const auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument("not hex");
  };
  lugh::Bytes out;
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) out.push_back(static_cast<unsigned char>(digit(text[i]) * 16 + digit(text[i + 1])));
  return out;
}

inline std::string to_hex(std::span<const unsigned char> data) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  for (const auto byte : data) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
  }
  return out;
}

inline lugh::Bytes repeated(unsigned char byte, std::size_t count) { return lugh::Bytes(count, byte); }

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "core/secure_bytes.h"

namespace lugh::encoding {

// Text forms of bytes. Each output is reserved at its final size first, so a string that
// is about to become a Secret is never copied on the way.

inline std::string hex(std::span<const unsigned char> data) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (const auto byte : data) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
  }
  return out;
}

// RFC 4648 base32, upper case and unpadded, as authenticator apps take a TOTP secret.
inline std::string base32(std::span<const unsigned char> data) {
  static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::string out;
  out.reserve((data.size() * 8 + 4) / 5);
  unsigned buffer = 0;
  int bits = 0;
  for (const auto byte : data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out.push_back(kAlphabet[(buffer >> (bits - 5)) & 0x1f]);
      bits -= 5;
    }
  }
  if (bits > 0) out.push_back(kAlphabet[(buffer << (5 - bits)) & 0x1f]);
  return out;
}

// Either case, no padding, nothing else. nullopt for anything that is not exactly that,
// including trailing bits that are not zero.
inline std::optional<SecureBytes> base32_decode(std::string_view text) {
  SecureBytes out;
  out.reserve(text.size() * 5 / 8);
  unsigned buffer = 0;
  int bits = 0;
  for (const char c : text) {
    int value;
    if (c >= 'A' && c <= 'Z') {
      value = c - 'A';
    } else if (c >= 'a' && c <= 'z') {
      value = c - 'a';
    } else if (c >= '2' && c <= '7') {
      value = c - '2' + 26;
    } else {
      return std::nullopt;
    }
    buffer = (buffer << 5) | static_cast<unsigned>(value);
    bits += 5;
    if (bits >= 8) {
      out.push_back(static_cast<unsigned char>(buffer >> (bits - 8)));
      bits -= 8;
    }
    buffer &= (1u << bits) - 1;
  }
  if (bits >= 5 || buffer != 0) return std::nullopt;
  return out;
}

// RFC 4648 base64url, unpadded: for tokens that go in a URL.
inline std::string base64url(std::span<const unsigned char> data) {
  static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((data.size() * 4 + 2) / 3);
  std::size_t i = 0;
  for (; i + 3 <= data.size(); i += 3) {
    const unsigned block = (unsigned{data[i]} << 16) | (unsigned{data[i + 1]} << 8) | data[i + 2];
    for (int shift = 18; shift >= 0; shift -= 6) out.push_back(kAlphabet[(block >> shift) & 0x3f]);
  }
  if (data.size() - i == 1) {
    const unsigned block = unsigned{data[i]} << 16;
    out.push_back(kAlphabet[(block >> 18) & 0x3f]);
    out.push_back(kAlphabet[(block >> 12) & 0x3f]);
  } else if (data.size() - i == 2) {
    const unsigned block = (unsigned{data[i]} << 16) | (unsigned{data[i + 1]} << 8);
    out.push_back(kAlphabet[(block >> 18) & 0x3f]);
    out.push_back(kAlphabet[(block >> 12) & 0x3f]);
    out.push_back(kAlphabet[(block >> 6) & 0x3f]);
  }
  return out;
}

}  // namespace lugh::encoding

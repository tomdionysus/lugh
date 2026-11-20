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
#include <string>
#include <string_view>

#include "lugh/core/secure_bytes.h"

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
inline std::optional<SecureBuffer> base32_decode(std::string_view text) {
  SecureBuffer out;
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

// RFC 4648 base64url, unpadded and exact: the alphabet only, no '=', and no length or
// trailing bits that an encoder would not make. nullopt for anything else, so one value has
// one spelling (a JWS is compared and hashed as it is written).
inline std::optional<Bytes> base64url_decode(std::string_view text) {
  if (text.size() % 4 == 1) return std::nullopt;
  const auto value = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
  };
  Bytes out;
  out.reserve(text.size() * 3 / 4);
  unsigned buffer = 0;
  int bits = 0;
  for (const char c : text) {
    const auto v = value(c);
    if (v < 0) return std::nullopt;
    buffer = (buffer << 6) | static_cast<unsigned>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<unsigned char>((buffer >> bits) & 0xff));
    }
    buffer &= (1u << bits) - 1;
  }
  if (buffer != 0) return std::nullopt;
  return out;
}

// The length of the UTF-8 sequence (RFC 3629) starting at `at`, or 0 for one that is not
// valid: overlong forms, surrogates and values past U+10FFFF included.
inline std::size_t utf8_length(std::string_view text, std::size_t at) {
  const auto byte = [&](std::size_t i) { return static_cast<unsigned char>(text[i]); };
  const auto first = byte(at);
  if (first < 0x80) return 1;
  std::size_t length;
  unsigned value;
  if ((first & 0xe0) == 0xc0) {
    length = 2;
    value = first & 0x1f;
  } else if ((first & 0xf0) == 0xe0) {
    length = 3;
    value = first & 0x0f;
  } else if ((first & 0xf8) == 0xf0) {
    length = 4;
    value = first & 0x07;
  } else {
    return 0;
  }
  if (at + length > text.size()) return 0;
  for (std::size_t i = 1; i < length; ++i) {
    if ((byte(at + i) & 0xc0) != 0x80) return 0;
    value = (value << 6) | (byte(at + i) & 0x3f);
  }
  static constexpr unsigned kLeast[] = {0, 0, 0x80, 0x800, 0x10000};
  if (value < kLeast[length] || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return 0;
  return length;
}

// Whether all of `text` is valid UTF-8.
inline bool valid_utf8(std::string_view text) {
  for (std::size_t i = 0; i < text.size();) {
    const auto length = utf8_length(text, i);
    if (length == 0) return false;
    i += length;
  }
  return true;
}

// Printable text: valid UTF-8 within `most` bytes, with no control character, C0, DEL or C1
// (U+0080 to U+009F). What a name, a topic level or a label may hold.
inline bool printable(std::string_view text, std::size_t most) {
  if (text.size() > most) return false;
  for (std::size_t i = 0; i < text.size();) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte < 0x20 || byte == 0x7f) return false;
    const auto length = utf8_length(text, i);
    if (length == 0) return false;
    if (length == 2 && byte == 0xc2 && static_cast<unsigned char>(text[i + 1]) <= 0x9f) return false;
    i += length;
  }
  return true;
}

// RFC 4648 base64 with padding, the standard alphabet, as HTTP Basic credentials are written
// (RFC 7617).
inline std::string base64(std::span<const unsigned char> data) {
  auto out = base64url(data);
  for (auto& c : out) {
    if (c == '-') {
      c = '+';
    } else if (c == '_') {
      c = '/';
    }
  }
  while (out.size() % 4 != 0) out.push_back('=');
  return out;
}

// RFC 4648 base64 with padding, the standard alphabet, as HTTP Basic credentials are written
// (RFC 7617). Exact, as base64url_decode() is: nothing for any other spelling.
inline std::optional<Bytes> base64_decode(std::string_view text) {
  if (text.size() % 4 != 0) return std::nullopt;
  std::string url(text);
  std::size_t padding = 0;
  while (!url.empty() && url.back() == '=' && padding < 2) {
    url.pop_back();
    ++padding;
  }
  for (auto& c : url) {
    if (c == '+') {
      c = '-';
    } else if (c == '/') {
      c = '_';
    } else if (c == '-' || c == '_' || c == '=') {
      return std::nullopt;
    }
  }
  return base64url_decode(url);
}

}  // namespace lugh::encoding

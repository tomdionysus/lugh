//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// CBOR (RFC 8949), as much as WebAuthn sends and no more (TODO/2026-11-15-p11-webauthn.md,
// W1): an authenticator's attestation object, its attested credential data and a COSE key.
// The decoder is strict, since every byte is an attacker's:
// - definite lengths only, each in its shortest form (CTAP2's canonical encoding);
// - integers that fit an int64_t;
// - byte and text strings, the text valid UTF-8;
// - arrays and maps, a map's keys never repeated;
// - false, true and null.
// Anything else is refused: tags, floats, undefined and other simple values, and
// indefinite lengths. So are a nesting deeper than kMostDepth and more than kMostItems
// items in all. Lengths are checked against what is left, and counts against the items still
// allowed, before anything is reserved, so what is made is bounded by kMostItems, not the input.
namespace lugh::webauthn::cbor {

inline constexpr std::size_t kMostDepth = 16;
inline constexpr std::size_t kMostItems = 4096;

struct Value {
  enum class Kind : std::uint8_t { integer, bytes, text, array, map, boolean, null };
  // A map's key and value. Declared here and defined below, since a std::pair of a type still
  // incomplete is refused by clang with libstdc++.
  struct Entry;

  Kind kind = Kind::null;
  std::int64_t integer = 0;
  bool boolean = false;
  // A byte string's bytes or a text string's UTF-8.
  std::string string;
  std::vector<Value> items;
  std::vector<Entry> entries;

  bool is_integer() const { return kind == Kind::integer; }
  bool is_bytes() const { return kind == Kind::bytes; }
  bool is_text() const { return kind == Kind::text; }
  bool is_map() const { return kind == Kind::map; }

  // A map's value under an integer or a text key; nothing when this is not a map or the
  // key is absent.
  const Value* find(std::int64_t key) const;
  const Value* find(std::string_view key) const;
};

struct Value::Entry {
  Value first;
  Value second;
};

// One item from the front of `in`. With `used`, what follows it is allowed and `*used`
// says where the item ended (attested credential data is followed by its COSE key, and
// that by extensions); without, the item must be all of `in`. Nothing for anything not
// as the header says.
std::optional<Value> decode(std::span<const std::uint8_t> in, std::size_t* used = nullptr);

}  // namespace lugh::webauthn::cbor

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/webauthn/cbor.h"

#include <algorithm>
#include <limits>

#include "lugh/core/encoding.h"

namespace lugh::webauthn::cbor {

namespace {

constexpr std::uint8_t kUnsigned = 0;
constexpr std::uint8_t kNegative = 1;
constexpr std::uint8_t kBytes = 2;
constexpr std::uint8_t kText = 3;
constexpr std::uint8_t kArray = 4;
constexpr std::uint8_t kMap = 5;
constexpr std::uint8_t kSimple = 7;

constexpr std::uint8_t kFalse = 20;
constexpr std::uint8_t kTrue = 21;
constexpr std::uint8_t kNull = 22;

class Decoder {
 public:
  explicit Decoder(std::span<const std::uint8_t> in) : _in(in) {}

  std::size_t at() const { return _at; }

  bool item(Value& out, std::size_t depth) {
    if (depth > kMostDepth || ++_items > kMostItems) return false;
    if (_at >= _in.size()) return false;
    const std::uint8_t initial = _in[_at++];
    const std::uint8_t major = initial >> 5;
    const std::uint8_t info = initial & 0x1f;

    if (major == kSimple) {
      if (info == kFalse || info == kTrue) {
        out.kind = Value::Kind::boolean;
        out.boolean = info == kTrue;
        return true;
      }
      if (info == kNull) {
        out.kind = Value::Kind::null;
        return true;
      }
      return false;
    }

    std::uint64_t argument;
    if (!this->argument(info, argument)) return false;

    switch (major) {
      case kUnsigned:
        if (argument > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return false;
        out.kind = Value::Kind::integer;
        out.integer = static_cast<std::int64_t>(argument);
        return true;
      case kNegative:
        // -1 - argument, which must not go below INT64_MIN.
        if (argument > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return false;
        out.kind = Value::Kind::integer;
        out.integer = -1 - static_cast<std::int64_t>(argument);
        return true;
      case kBytes:
      case kText: {
        if (argument > _in.size() - _at) return false;
        const auto length = static_cast<std::size_t>(argument);
        out.kind = major == kBytes ? Value::Kind::bytes : Value::Kind::text;
        out.string.assign(reinterpret_cast<const char*>(_in.data() + _at), length);
        _at += length;
        return major == kBytes || encoding::valid_utf8(out.string);
      }
      case kArray: {
        // Each item takes at least a byte, so a count past what is left is a lie.
        if (argument > _in.size() - _at) return false;
        out.kind = Value::Kind::array;
        out.items.resize(static_cast<std::size_t>(argument));
        for (auto& each : out.items)
          if (!item(each, depth + 1)) return false;
        return true;
      }
      case kMap: {
        if (argument > (_in.size() - _at) / 2) return false;
        out.kind = Value::Kind::map;
        const auto count = static_cast<std::size_t>(argument);
        out.entries.reserve(count);
        std::vector<std::pair<std::size_t, std::size_t>> keys;
        keys.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
          Value::Entry entry;
          const auto key_from = _at;
          if (!item(entry.first, depth + 1)) return false;
          const std::pair<std::size_t, std::size_t> key{key_from, _at - key_from};
          // A key repeated is two meanings for one name: refused, compared as encoded,
          // which canonical encoding makes one spelling.
          for (const auto& seen : keys) {
            if (seen.second == key.second &&
                std::equal(_in.begin() + static_cast<std::ptrdiff_t>(seen.first), _in.begin() + static_cast<std::ptrdiff_t>(seen.first + seen.second),
                           _in.begin() + static_cast<std::ptrdiff_t>(key.first)))
              return false;
          }
          keys.push_back(key);
          if (!item(entry.second, depth + 1)) return false;
          out.entries.push_back(std::move(entry));
        }
        return true;
      }
      default:
        // Tags (6) are refused.
        return false;
    }
  }

 private:
  // The argument after the initial byte, in its shortest form only (RFC 8949 4.2.1).
  bool argument(std::uint8_t info, std::uint64_t& out) {
    if (info < 24) {
      out = info;
      return true;
    }
    std::size_t length;
    std::uint64_t least;
    switch (info) {
      case 24:
        length = 1;
        least = 24;
        break;
      case 25:
        length = 2;
        least = 0x100;
        break;
      case 26:
        length = 4;
        least = 0x10000;
        break;
      case 27:
        length = 8;
        least = 0x100000000ull;
        break;
      default:
        // 28 to 30 are reserved, 31 is an indefinite length.
        return false;
    }
    if (length > _in.size() - _at) return false;
    out = 0;
    for (std::size_t i = 0; i < length; ++i) out = (out << 8) | _in[_at++];
    return out >= least;
  }

  std::span<const std::uint8_t> _in;
  std::size_t _at = 0;
  std::size_t _items = 0;
};

}  // namespace

const Value* Value::find(std::int64_t key) const {
  if (kind != Kind::map) return nullptr;
  for (const auto& [name, value] : entries)
    if (name.kind == Kind::integer && name.integer == key) return &value;
  return nullptr;
}

const Value* Value::find(std::string_view key) const {
  if (kind != Kind::map) return nullptr;
  for (const auto& [name, value] : entries)
    if (name.kind == Kind::text && name.string == key) return &value;
  return nullptr;
}

std::optional<Value> decode(std::span<const std::uint8_t> in, std::size_t* used) {
  Decoder decoder(in);
  Value out;
  if (!decoder.item(out, 0)) return std::nullopt;
  if (used) {
    *used = decoder.at();
  } else if (decoder.at() != in.size()) {
    return std::nullopt;
  }
  return out;
}

}  // namespace lugh::webauthn::cbor

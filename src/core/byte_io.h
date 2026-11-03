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

namespace lugh {

// Big-endian fields into a buffer, for the binary formats Lugh owns. Templated on the buffer
// so a format holding keys is built in SecureBytes and never anywhere else.
template <typename Buffer>
class ByteWriter {
 public:
  explicit ByteWriter(Buffer& out) : _out(out) {}

  void u8(std::uint8_t value) { _out.push_back(value); }

  void u16(std::uint16_t value) {
    _out.push_back(static_cast<unsigned char>(value >> 8));
    _out.push_back(static_cast<unsigned char>(value));
  }

  void u64(std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) _out.push_back(static_cast<unsigned char>(value >> shift));
  }

  void u32(std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) _out.push_back(static_cast<unsigned char>(value >> shift));
  }

  void bytes(std::span<const unsigned char> data) { _out.insert(_out.end(), data.begin(), data.end()); }

  void text(std::string_view data) {
    for (const char c : data) _out.push_back(static_cast<unsigned char>(c));
  }

  // A string with its length in front, for a record's fields. The caller bounds it first.
  void field(std::string_view data) {
    u16(static_cast<std::uint16_t>(data.size()));
    text(data);
  }

 private:
  Buffer& _out;
};

// The other way, refusing to read past the end: every read answers nullopt once the input
// is short, and the parser gives up.
class ByteReader {
 public:
  explicit ByteReader(std::span<const unsigned char> data) : _data(data) {}

  std::optional<std::uint8_t> u8() {
    if (remaining() < 1) return std::nullopt;
    return _data[_offset++];
  }

  std::optional<std::uint16_t> u16() {
    if (remaining() < 2) return std::nullopt;
    const auto value = static_cast<std::uint16_t>((_data[_offset] << 8) | _data[_offset + 1]);
    _offset += 2;
    return value;
  }

  std::optional<std::uint32_t> u32() {
    if (remaining() < 4) return std::nullopt;
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) value = (value << 8) | _data[_offset++];
    return value;
  }

  std::optional<std::uint64_t> u64() {
    if (remaining() < 8) return std::nullopt;
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8) | _data[_offset++];
    return value;
  }

  std::optional<std::span<const unsigned char>> bytes(std::size_t count) {
    if (remaining() < count) return std::nullopt;
    const auto out = _data.subspan(_offset, count);
    _offset += count;
    return out;
  }

  std::optional<std::string> field() {
    const auto length = u16();
    if (!length) return std::nullopt;
    const auto data = bytes(*length);
    if (!data) return std::nullopt;
    return std::string(data->begin(), data->end());
  }

  // Everything left.
  std::span<const unsigned char> rest() {
    const auto out = _data.subspan(_offset);
    _offset = _data.size();
    return out;
  }

  std::size_t offset() const { return _offset; }
  std::size_t remaining() const { return _data.size() - _offset; }
  bool done() const { return remaining() == 0; }

 private:
  std::span<const unsigned char> _data;
  std::size_t _offset = 0;
};

}  // namespace lugh

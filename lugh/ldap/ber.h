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
#include <vector>

// BER as RFC 4511 section 5.1 restricts it: definite lengths only, single-byte tags, and strings
// primitive. Every read is bounded by the bytes it was given, and what is malformed is answered as
// nothing, never thrown: it came from the network. Nothing here copies but the text it hands back.
namespace lugh::ldap::ber {

using Bytes = std::span<const unsigned char>;

inline constexpr std::uint8_t kBoolean = 0x01;
inline constexpr std::uint8_t kInteger = 0x02;
inline constexpr std::uint8_t kOctetString = 0x04;
inline constexpr std::uint8_t kEnumerated = 0x0A;
inline constexpr std::uint8_t kSequence = 0x30;
inline constexpr std::uint8_t kSet = 0x31;

// The most length bytes accepted, which is more than any message Lugh takes can need.
inline constexpr std::size_t kMostLengthBytes = 4;

// One element: its tag, and its contents, still inside the buffer it was read from.
struct Element {
  std::uint8_t tag = 0;
  Bytes content;

  bool constructed() const { return (tag & 0x20) != 0; }
  std::string_view text() const { return {reinterpret_cast<const char*>(content.data()), content.size()}; }
};

// Takes elements off the front of a run of bytes.
class Reader {
 public:
  explicit Reader(Bytes bytes) : _rest(bytes) {}

  bool empty() const { return _rest.empty(); }
  // The next element, moved past; nothing if what is next is malformed or cut short.
  std::optional<Element> next();
  // The next element's tag, not moved past.
  std::optional<std::uint8_t> peek_tag() const;

 private:
  Bytes _rest;
};

// How far a buffer holds a whole element, for a connection reading a stream.
struct Frame {
  enum class State {
    // More bytes are needed before anything can be said.
    partial,
    // `size` bytes are one element.
    complete,
    // No more bytes will help: a bad tag or length, or an element past `most`.
    invalid,
  };
  State state = State::partial;
  std::size_t size = 0;
};
Frame frame(Bytes buffer, std::size_t most);

// The values, each nothing for contents that cannot be that value.
std::optional<std::int64_t> integer(const Element& element);
std::optional<bool> boolean(const Element& element);

// Builds an encoded element, nested with begin() and end(). Lengths are minimal.
class Writer {
 public:
  void begin(std::uint8_t tag);
  void end();
  void octets(std::uint8_t tag, std::string_view value);
  void integer(std::uint8_t tag, std::int64_t value);
  void boolean(std::uint8_t tag, bool value);
  // An element already encoded.
  void raw(std::string_view encoded);

  // What has been written. Every begin() must have had its end().
  const std::string& bytes() const { return _out; }

 private:
  std::string _out;
  std::vector<std::size_t> _open;
};

}  // namespace lugh::ldap::ber

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/ber.h"

#include <stdexcept>

namespace lugh::ldap::ber {

namespace {

// The tag and length at the front of `bytes`: where the contents start and how long they are.
struct Header {
  std::uint8_t tag = 0;
  std::size_t header_size = 0;
  std::size_t content_size = 0;
};

enum class Parsed { partial, complete, invalid };

Parsed parse_header(Bytes bytes, Header& out) {
  if (bytes.empty()) return Parsed::partial;
  out.tag = bytes[0];
  // The high tag number form: no LDAP tag needs it.
  if ((out.tag & 0x1F) == 0x1F) return Parsed::invalid;
  if (bytes.size() < 2) return Parsed::partial;
  const auto first = bytes[1];
  if (first < 0x80) {
    out.header_size = 2;
    out.content_size = first;
    return Parsed::complete;
  }
  // 0x80 is the indefinite form, which RFC 4511 section 5.1 forbids.
  const std::size_t count = first & 0x7F;
  if (count == 0 || count > kMostLengthBytes) return Parsed::invalid;
  if (bytes.size() < 2 + count) return Parsed::partial;
  std::size_t length = 0;
  for (std::size_t i = 0; i < count; ++i) length = (length << 8) | bytes[2 + i];
  out.header_size = 2 + count;
  out.content_size = length;
  return Parsed::complete;
}

std::string length_bytes(std::size_t length) {
  std::string out;
  if (length < 0x80) {
    out.push_back(static_cast<char>(length));
    return out;
  }
  std::string digits;
  for (std::size_t rest = length; rest != 0; rest >>= 8) digits.insert(digits.begin(), static_cast<char>(rest & 0xFF));
  out.push_back(static_cast<char>(0x80 | digits.size()));
  return out + digits;
}

}  // namespace

std::optional<Element> Reader::next() {
  Header header;
  if (parse_header(_rest, header) != Parsed::complete) return std::nullopt;
  if (header.content_size > _rest.size() - header.header_size) return std::nullopt;
  Element out{header.tag, _rest.subspan(header.header_size, header.content_size)};
  _rest = _rest.subspan(header.header_size + header.content_size);
  return out;
}

std::optional<std::uint8_t> Reader::peek_tag() const {
  if (_rest.empty()) return std::nullopt;
  return _rest[0];
}

Frame frame(Bytes buffer, std::size_t most) {
  Header header;
  switch (parse_header(buffer, header)) {
    case Parsed::partial:
      return {Frame::State::partial, 0};
    case Parsed::invalid:
      return {Frame::State::invalid, 0};
    case Parsed::complete:
      break;
  }
  if (header.content_size > most || header.header_size + header.content_size > most) return {Frame::State::invalid, 0};
  const auto whole = header.header_size + header.content_size;
  if (buffer.size() < whole) return {Frame::State::partial, 0};
  return {Frame::State::complete, whole};
}

std::optional<std::int64_t> integer(const Element& element) {
  const auto bytes = element.content;
  if (bytes.empty() || bytes.size() > 8) return std::nullopt;
  std::uint64_t value = (bytes[0] & 0x80) != 0 ? ~std::uint64_t{0} : 0;
  for (const auto byte : bytes) value = (value << 8) | byte;
  return static_cast<std::int64_t>(value);
}

std::optional<bool> boolean(const Element& element) {
  if (element.content.size() != 1) return std::nullopt;
  return element.content[0] != 0;
}

void Writer::begin(std::uint8_t tag) {
  _out.push_back(static_cast<char>(tag));
  _open.push_back(_out.size());
}

void Writer::end() {
  if (_open.empty()) throw std::logic_error("ber::Writer::end without begin");
  const auto at = _open.back();
  _open.pop_back();
  _out.insert(at, length_bytes(_out.size() - at));
}

void Writer::octets(std::uint8_t tag, std::string_view value) {
  _out.push_back(static_cast<char>(tag));
  _out += length_bytes(value.size());
  _out += value;
}

void Writer::integer(std::uint8_t tag, std::int64_t value) {
  std::string digits;
  auto rest = value;
  // Fewest bytes that keep the sign: arithmetic shifts until only the sign is left.
  for (;;) {
    const auto byte = static_cast<unsigned char>(rest & 0xFF);
    digits.insert(digits.begin(), static_cast<char>(byte));
    rest >>= 8;
    if ((rest == 0 && (byte & 0x80) == 0) || (rest == -1 && (byte & 0x80) != 0)) break;
  }
  octets(tag, digits);
}

void Writer::boolean(std::uint8_t tag, bool value) { octets(tag, value ? std::string_view("\xFF", 1) : std::string_view("\x00", 1)); }

}  // namespace lugh::ldap::ber

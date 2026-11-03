//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "network/cidr.h"

#include <cctype>
#include <vector>

namespace lugh::network {

namespace {

std::vector<unsigned char> bytes_of(const boost::asio::ip::address& address) {
  if (address.is_v4()) {
    const auto bytes = address.to_v4().to_bytes();
    return {bytes.begin(), bytes.end()};
  }

  const auto bytes = address.to_v6().to_bytes();
  return {bytes.begin(), bytes.end()};
}

// Whether the first `bits` bits of the two are the same.
bool same_prefix(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b, unsigned bits) {
  const auto whole = bits / 8;
  for (unsigned i = 0; i < whole; ++i) {
    if (a[i] != b[i]) return false;
  }

  const auto rest = bits % 8;
  if (rest == 0) return true;

  const auto mask = static_cast<unsigned char>(0xFF << (8 - rest));
  return (a[whole] & mask) == (b[whole] & mask);
}

bool host_bits_clear(const std::vector<unsigned char>& bytes, unsigned bits) {
  for (unsigned i = 0; i < bytes.size() * 8; ++i) {
    if (i < bits) continue;
    if (bytes[i / 8] & (0x80 >> (i % 8))) return false;
  }
  return true;
}

}  // namespace

boost::asio::ip::address unmapped(const boost::asio::ip::address& address) {
  if (address.is_v6() && address.to_v6().is_v4_mapped()) {
    return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, address.to_v6());
  }
  return address;
}

std::optional<Cidr> Cidr::parse(const std::string& text) {
  const auto slash = text.find('/');
  const auto address_text = slash == std::string::npos ? text : text.substr(0, slash);

  boost::system::error_code ec;
  const auto address = boost::asio::ip::make_address(address_text, ec);
  if (ec) return std::nullopt;

  const unsigned width = address.is_v4() ? 32 : 128;
  if (slash == std::string::npos) return Cidr(address, width);

  const auto prefix_text = text.substr(slash + 1);
  if (prefix_text.empty() || prefix_text.size() > 3) return std::nullopt;
  for (const char c : prefix_text) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
  }

  const auto prefix = static_cast<unsigned>(std::stoul(prefix_text));
  if (prefix > width) return std::nullopt;
  if (!host_bits_clear(bytes_of(address), prefix)) return std::nullopt;

  return Cidr(address, prefix);
}

bool Cidr::contains(const boost::asio::ip::address& address) const {
  const auto candidate = unmapped(address);
  if (candidate.is_v4() != _address.is_v4()) return false;

  return same_prefix(bytes_of(candidate), bytes_of(_address), _prefix);
}

std::string Cidr::to_string() const { return _address.to_string() + "/" + std::to_string(_prefix); }

}  // namespace lugh::network

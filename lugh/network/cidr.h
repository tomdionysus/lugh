//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/ip/address.hpp>
#include <optional>
#include <string>

namespace lugh::network {

// An address range, IPv4 or IPv6, as "10.0.0.0/8": the proxies the listener trusts, and
// later the networks an app password is limited to.
class Cidr {
 public:
  // nullopt for anything that is not an address, an address and a prefix length in range,
  // or that has host bits set: "10.0.0.1/8" is more likely a mistake than a network. A
  // bare address is the one host, /32 or /128.
  static std::optional<Cidr> parse(const std::string& text);

  // An IPv4-mapped IPv6 address is matched as the IPv4 address it carries.
  bool contains(const boost::asio::ip::address& address) const;

  const boost::asio::ip::address& address() const { return _address; }
  unsigned prefix() const { return _prefix; }
  std::string to_string() const;

 private:
  Cidr(boost::asio::ip::address address, unsigned prefix) : _address(std::move(address)), _prefix(prefix) {}

  boost::asio::ip::address _address;
  unsigned _prefix;
};

// A socket bound to :: reports IPv4 peers as ::ffff:a.b.c.d; this is the IPv4 address.
boost::asio::ip::address unmapped(const boost::asio::ip::address& address);

}  // namespace lugh::network

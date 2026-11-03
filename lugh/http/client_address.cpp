//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "http/client_address.h"

#include <utility>

namespace lugh::http {

namespace {

std::string trim(const std::string& text) {
  const auto first = text.find_first_not_of(" \t");
  if (first == std::string::npos) return {};
  const auto last = text.find_last_not_of(" \t");
  return text.substr(first, last - first + 1);
}

// The address as text, or nullopt when it is not one.
std::optional<std::string> address_text(const std::string& text) {
  boost::system::error_code ec;
  const auto address = boost::asio::ip::make_address(text, ec);
  if (ec) return std::nullopt;
  return network::unmapped(address).to_string();
}

}  // namespace

ClientAddress::ClientAddress(std::vector<network::Cidr> trusted_proxies) : _trusted_proxies(std::move(trusted_proxies)) {}

std::string ClientAddress::resolve(const boost::asio::ip::address& peer, const HttpRequest& request) const {
  const auto direct = network::unmapped(peer);

  for (const auto& network : _trusted_proxies) {
    if (!network.contains(direct)) continue;
    if (auto forwarded = _last_forwarded(request)) return *forwarded;
    break;
  }

  return direct.to_string();
}

// A proxy appends to the last X-Forwarded-For line, so the last entry of the last line.
std::optional<std::string> ClientAddress::_last_forwarded(const HttpRequest& request) {
  std::string last_line;
  for (auto [it, end] = request.equal_range("X-Forwarded-For"); it != end; ++it) last_line = std::string(it->value());
  if (last_line.empty()) return std::nullopt;

  const auto comma = last_line.rfind(',');
  const auto entry = trim(comma == std::string::npos ? last_line : last_line.substr(comma + 1));

  return address_text(entry);
}

}  // namespace lugh::http

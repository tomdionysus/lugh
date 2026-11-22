//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/client_address.h"

namespace lugh::http {

ClientAddress::ClientAddress(std::vector<network::Prefix> trusted_proxies) : _trusted_proxies(std::move(trusted_proxies)) {}

std::string ClientAddress::resolve(const boost::asio::ip::address& peer, const HttpRequest& request) const {
  // Several X-Forwarded-For lines are one list, in order (RFC 9110 5.3).
  std::string forwarded;
  for (auto [it, end] = request.equal_range("X-Forwarded-For"); it != end; ++it) {
    if (!forwarded.empty()) forwarded += ',';
    forwarded.append(it->value());
  }
  return network::unmapped(dannan::listen::forwarded_for(forwarded, _trusted_proxies, network::unmapped(peer))).to_string();
}

}  // namespace lugh::http

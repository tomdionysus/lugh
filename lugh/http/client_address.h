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
#include <vector>

#include "lugh/http/http_types.h"
#include "lugh/network/cidr.h"

namespace lugh::http {

// Who a request is from, for the back-off and the audit log.
//
// Lugh terminates its own TLS, so the socket's peer is the client unless the operator has
// put a proxy in front and named it in proxy.trusted_networks. A request from a trusted
// proxy is taken at the last entry of X-Forwarded-For, the one that proxy appended; earlier
// entries are whatever the client sent and are never read. Any other peer is taken at its
// socket's address, and any forwarding header it sends is ignored: anyone can write one.
class ClientAddress {
 public:
  explicit ClientAddress(std::vector<network::Cidr> trusted_proxies);

  std::string resolve(const boost::asio::ip::address& peer, const HttpRequest& request) const;

 private:
  static std::optional<std::string> _last_forwarded(const HttpRequest& request);

  std::vector<network::Cidr> _trusted_proxies;
};

}  // namespace lugh::http

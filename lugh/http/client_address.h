//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/ip/address.hpp>
#include <string>
#include <vector>

#include "dannan/listen/limits.h"
#include "lugh/http/http_types.h"
#include "lugh/network/prefix.h"

namespace lugh::http {

// Who a request is from, for the back-off and the audit log.
//
// Lugh terminates its own TLS, so the socket's peer is the client unless the operator has
// put proxies in front and named them in proxy.trusted_networks. From a trusted proxy,
// X-Forwarded-For is read from the right, past every trusted proxy, to the first address that
// is not one (Dannan's forwarded_for); entries left of it are whatever the client sent and are
// never read, and an entry that is not an address stops the walk short. Any other peer is
// taken at its socket's address, and any forwarding header it sends is ignored: anyone can
// write one.
class ClientAddress {
 public:
  explicit ClientAddress(std::vector<network::Prefix> trusted_proxies);

  std::string resolve(const boost::asio::ip::address& peer, const HttpRequest& request) const;

 private:
  std::vector<dannan::listen::Prefix> _trusted_proxies;
};

}  // namespace lugh::http

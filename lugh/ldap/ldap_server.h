//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <map>
#include <memory>
#include <string>

#include "dannan/contract/thread_safety.h"
#include "dannan/status/log.h"
#include "lugh/core/status.h"
#include "lugh/http/http_types.h"
#include "lugh/ldap/connection.h"

namespace lugh::ldap {

// An LDAP listener (TODO/2026-11-04-ldap.md, "Transport and limits"): LDAPS, or plaintext until
// StartTLS. Accepts up to `most_connections`, and past that closes a new one at once.
class LdapServer : public std::enable_shared_from_this<LdapServer> {
 public:
  static constexpr std::size_t kMostConnections = 4096;

  // `tls` says which of the two this listener is.
  LdapServer(std::shared_ptr<dannan::status::LogSink> log, http::net::io_context& io_context, ConnectionParts parts, bool tls,
             std::size_t most_connections = kMostConnections);

  // Binds and listens. A failure is the caller's to act on.
  Status listen(const std::string& address, std::uint16_t port);

  void start();

  // Stops accepting, and closes the connections there are.
  void stop();

  std::uint16_t port() const;

 private:
  void _accept();

  dannan::status::ScopedLogger _logger;
  http::net::io_context& _io_context;
  http::net::ip::tcp::acceptor _acceptor;
  ConnectionParts _parts;
  bool _tls = false;
  std::size_t _most_connections;

  mutable dannan::contract::Mutex _mutex;
  std::map<Connection*, std::weak_ptr<Connection>> _connections DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::ldap

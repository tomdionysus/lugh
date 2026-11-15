//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include "dannan/listen/listener.h"
#include "dannan/status/log.h"
#include "lugh/core/status.h"
#include "lugh/http/http_types.h"
#include "lugh/ldap/connection.h"

namespace lugh::ldap {

// An LDAP listener (TODO/2026-11-04-ldap.md, "Transport and limits"): LDAPS, or plaintext until
// StartTLS. Accepts through Dannan's public listener (dannan::listen), which holds the TLS, the
// handshake's deadline and StartTLS's upgrade; the messages are Lugh's. Accepts up to
// `most_connections`, and past that closes a new one at once.
class LdapServer : public std::enable_shared_from_this<LdapServer> {
 public:
  static constexpr std::size_t kMostConnections = 4096;

  // `tls` says which of the two this listener is.
  LdapServer(std::shared_ptr<dannan::status::LogSink> log, http::net::io_context& io_context, ConnectionParts parts, bool tls,
             std::size_t most_connections = kMostConnections);
  ~LdapServer();

  // Binds and listens, or adopts `inherited`, a listening socket systemd passed. A failure is the
  // caller's to act on. Connections are served from start().
  Status listen(const std::string& address, std::uint16_t port, std::optional<int> inherited = std::nullopt);

  void start();

  // Stops accepting, and closes the connections there are.
  void stop();

  std::uint16_t port() const;

 private:
  void _served(std::shared_ptr<dannan::listen::Stream> stream);

  dannan::status::ScopedLogger _logger;
  http::net::io_context& _io_context;
  ConnectionParts _parts;
  bool _tls = false;
  std::size_t _most_connections;
  std::unique_ptr<dannan::listen::StreamListener> _listener;
  std::atomic<bool> _started{false};
};

}  // namespace lugh::ldap

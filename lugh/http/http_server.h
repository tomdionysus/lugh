//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/listen/certificates.h"
#include "dannan/listen/listener.h"
#include "dannan/status/log.h"
#include "lugh/core/status.h"
#include "lugh/http/client_address.h"
#include "lugh/http/http_types.h"

namespace lugh::http {

// Everything a connection needs from the server, fixed when the server starts. Sessions
// hold this rather than the server, so the server owns nothing they reach into.
struct HttpPipeline {
  struct Limits {
    // A request body over this is refused with 413. Nothing Lugh takes comes near it: the
    // largest is a pushed authorisation request.
    std::size_t body_bytes = 64 * 1024;

    // A connection that sends nothing for this long is closed.
    std::chrono::seconds idle{30};

    // A client that opens a connection and does not finish the TLS handshake in this long
    // is dropped, so half-open handshakes cannot hold the listener.
    std::chrono::seconds handshake{10};
  };

  dannan::status::ScopedLogger logger;
  std::shared_ptr<ClientAddress> client_address;
  std::vector<HttpMiddleware> middlewares;
  Limits limits;
  // The mTLS listener: a client certificate presented is handed to the routes
  // (lugh/http/client_certificate.h).
  bool client_certificates = false;
};

// Beast over TLS 1.3, and only that: there is no plaintext listener. Accepts through Dannan's
// public listener (dannan::listen): the TLS handshake, its deadline and a bounded close are the
// listener's, the requests Lugh's. Runs on an io_context it is given and does not own, so main
// decides the threads. Every response leaves with the security headers, whatever the middleware
// set.
class HttpServer : public std::enable_shared_from_this<HttpServer> {
 public:
  // `certificates` are the operator's chain, key and client CA; with `client_certificates`, the
  // listener is the mTLS one, asking every connection for a certificate, which never ends the
  // handshake: the routes judge it.
  HttpServer(std::shared_ptr<dannan::status::LogSink> log, net::io_context& io_context, std::shared_ptr<dannan::listen::Certificates> certificates,
             std::shared_ptr<ClientAddress> client_address, HttpPipeline::Limits limits = {}, bool client_certificates = false);
  ~HttpServer();

  // In the order they run. Before start().
  void middleware_add(HttpMiddleware middleware);

  // Binds and listens, or adopts `inherited`, a listening socket systemd passed. A failure is the
  // caller's to act on. Connections are served from start().
  Status listen(const std::string& address, std::uint16_t port, std::optional<int> inherited = std::nullopt);

  void start();

  // Stops accepting and closes every connection, each within the listener's close bound.
  void stop();

  // The port being listened on, which differs from the one asked for when that was zero.
  std::uint16_t port() const;

 private:
  void _served(std::shared_ptr<dannan::listen::Stream> stream);

  dannan::status::ScopedLogger _logger;
  net::io_context& _io_context;
  std::shared_ptr<dannan::listen::Certificates> _certificates;
  std::shared_ptr<ClientAddress> _client_address;
  HttpPipeline::Limits _limits;
  bool _client_certificates = false;
  std::vector<HttpMiddleware> _middlewares;
  std::unique_ptr<dannan::listen::StreamListener> _listener;
  mutable dannan::contract::Mutex _mutex;
  std::shared_ptr<const HttpPipeline> _pipeline DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::http

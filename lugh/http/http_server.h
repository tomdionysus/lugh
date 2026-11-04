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
#include <string>
#include <vector>

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
};

// Beast over TLS 1.3, and only that: there is no plaintext listener. Runs on an io_context
// it is given and does not own, so main decides the threads. Every response leaves with the
// security headers, whatever the middleware set.
class HttpServer : public std::enable_shared_from_this<HttpServer> {
 public:
  HttpServer(std::shared_ptr<dannan::status::LogSink> log, net::io_context& io_context, std::shared_ptr<ssl::context> tls,
             std::shared_ptr<ClientAddress> client_address, HttpPipeline::Limits limits = {});

  // In the order they run. Before start().
  void middleware_add(HttpMiddleware middleware);

  // Binds and listens. A failure is the caller's to act on.
  Status listen(const std::string& address, std::uint16_t port);

  void start();

  // Stops accepting. Connections in flight finish when the io_context stops.
  void stop();

  // The port being listened on, which differs from the one asked for when that was zero.
  std::uint16_t port() const;

 private:
  void _accept();

  dannan::status::ScopedLogger _logger;
  net::io_context& _io_context;
  net::ip::tcp::acceptor _acceptor;
  std::shared_ptr<ssl::context> _tls;
  std::shared_ptr<ClientAddress> _client_address;
  HttpPipeline::Limits _limits;
  std::vector<HttpMiddleware> _middlewares;
  std::shared_ptr<const HttpPipeline> _pipeline;
};

}  // namespace lugh::http

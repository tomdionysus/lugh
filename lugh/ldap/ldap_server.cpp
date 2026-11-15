//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/ldap_server.h"

#include <stdexcept>
#include <system_error>

namespace lugh::ldap {

namespace net = http::net;

LdapServer::LdapServer(std::shared_ptr<dannan::status::LogSink> log, net::io_context& io_context, ConnectionParts parts, bool tls, std::size_t most_connections)
    : _logger(std::move(log), "ldap"), _io_context(io_context), _parts(std::move(parts)), _tls(tls), _most_connections(most_connections) {}

LdapServer::~LdapServer() = default;

Status LdapServer::listen(const std::string& address, std::uint16_t port, std::optional<int> inherited) {
  boost::system::error_code ec;
  net::ip::make_address(address, ec);
  if (ec) return Status::failure("not an address to listen on: " + address);

  dannan::listen::ListenerConfig config;
  config.name = _tls ? "ldaps" : "ldap";
  config.host = address;
  config.port = port;
  config.inherited = inherited;
  config.certificates = _parts.certificates;
  // TLS 1.3 only, as LDAP has been (whether to allow 1.2 for old clients is an open question).
  config.tls.minimum = dannan::listen::TlsVersion::tls13;
  config.tls.client_certificates = dannan::listen::ClientCertificates::never;
  // Plaintext until StartTLS: the upgrade is Dannan's, when Lugh hands it the answer.
  config.start_tls = !_tls;
  config.handshake_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(_parts.handshake);
  // One past the limit is closed at once, at accept.
  config.max_connections = _most_connections;
  const auto where = address + ":" + std::to_string(port);
  try {
    _listener = std::make_unique<dannan::listen::StreamListener>(_io_context, std::move(config));
    _listener->start(_io_context.get_executor(), [weak = weak_from_this()](std::shared_ptr<dannan::listen::Stream> stream) {
      if (const auto self = weak.lock()) {
        self->_served(std::move(stream));
      } else {
        stream->abort();
      }
    });
  } catch (const std::system_error& e) {
    _listener.reset();
    return Status::failure("cannot listen on " + where + ": " + e.what());
  } catch (const std::runtime_error& e) {
    _listener.reset();
    return Status::failure("cannot set up TLS for " + where + ": " + e.what());
  }
  return Status::success();
}

void LdapServer::start() {
  _started = true;
  _logger.info("LDAP listening on port " + std::to_string(port()) + (_tls ? ", LDAPS, TLS 1.3 only" : ", plaintext until StartTLS, TLS 1.3 only"));
}

void LdapServer::_served(std::shared_ptr<dannan::listen::Stream> stream) {
  // Accepted before start(): nothing is ready to answer it.
  if (!_started) return stream->abort();
  std::make_shared<Connection>(std::move(stream), _parts)->start();
}

void LdapServer::stop() {
  // The listener closes every stream it handed up; each connection's read then ends it.
  if (_listener) _listener->stop();
}

std::uint16_t LdapServer::port() const { return _listener ? _listener->port() : 0; }

}  // namespace lugh::ldap

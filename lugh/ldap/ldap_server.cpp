//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/ldap_server.h"

#include <vector>

namespace lugh::ldap {

namespace net = http::net;
using tcp = net::ip::tcp;

LdapServer::LdapServer(std::shared_ptr<dannan::status::LogSink> log, net::io_context& io_context, ConnectionParts parts, bool tls, std::size_t most_connections)
    : _logger(std::move(log), "ldap"),
      _io_context(io_context),
      _acceptor(io_context),
      _parts(std::move(parts)),
      _tls(tls),
      _most_connections(most_connections) {}

Status LdapServer::listen(const std::string& address, std::uint16_t port) {
  boost::system::error_code ec;
  const auto ip = net::ip::make_address(address, ec);
  if (ec) return Status::failure("not an address to listen on: " + address);
  const tcp::endpoint endpoint(ip, port);
  const auto where = address + ":" + std::to_string(port);
  _acceptor.open(endpoint.protocol(), ec);
  if (ec) return Status::failure("cannot open a socket for " + where + ": " + ec.message());
  _acceptor.set_option(net::socket_base::reuse_address(true), ec);
  if (ec) return Status::failure("cannot set address reuse on " + where + ": " + ec.message());
  _acceptor.bind(endpoint, ec);
  if (ec) return Status::failure("cannot bind " + where + ": " + ec.message());
  _acceptor.listen(net::socket_base::max_listen_connections, ec);
  if (ec) return Status::failure("cannot listen on " + where + ": " + ec.message());
  return Status::success();
}

void LdapServer::start() {
  _logger.info("LDAP listening on port " + std::to_string(port()) + (_tls ? ", LDAPS, TLS 1.3 only" : ", plaintext until StartTLS, TLS 1.3 only"));
  net::dispatch(_acceptor.get_executor(), [self = shared_from_this()] { self->_accept(); });
}

void LdapServer::stop() {
  net::post(_acceptor.get_executor(), [self = shared_from_this()] {
    boost::system::error_code ignored;
    self->_acceptor.close(ignored);
    std::vector<std::shared_ptr<Connection>> open;
    {
      dannan::contract::Lock state(self->_mutex);
      for (const auto& [raw, weak] : self->_connections) {
        if (auto connection = weak.lock()) open.push_back(std::move(connection));
      }
      self->_connections.clear();
    }
    for (const auto& connection : open) connection->close();
  });
}

std::uint16_t LdapServer::port() const {
  boost::system::error_code ec;
  const auto endpoint = _acceptor.local_endpoint(ec);
  return ec ? 0 : endpoint.port();
}

void LdapServer::_accept() {
  _acceptor.async_accept(net::make_strand(_io_context), [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
    if (ec == net::error::operation_aborted || !self->_acceptor.is_open()) return;
    if (ec) {
      self->_logger.warn("Accept failed: " + ec.message());
    } else {
      std::shared_ptr<Connection> connection;
      {
        dannan::contract::Lock state(self->_mutex);
        for (auto one = self->_connections.begin(); one != self->_connections.end();) {
          one = one->second.expired() ? self->_connections.erase(one) : std::next(one);
        }
        if (self->_connections.size() < self->_most_connections) {
          connection = std::make_shared<Connection>(std::move(socket), self->_parts, self->_tls);
          self->_connections.emplace(connection.get(), connection);
        }
      }
      // One past the limit is simply closed, by the socket going out of scope.
      if (connection) connection->start();
    }
    self->_accept();
  });
}

}  // namespace lugh::ldap

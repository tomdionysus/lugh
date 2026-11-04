//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/http_server.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <exception>
#include <optional>
#include <utility>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/http/api_json.h"
#include "lugh/http/client_certificate.h"

namespace lugh::http {

namespace {

using tcp = net::ip::tcp;
using Stream = beast::ssl_stream<beast::tcp_stream>;

// One connection: a TLS handshake, then any number of requests on it in turn. Everything
// runs on the connection's strand.
class HttpSession : public std::enable_shared_from_this<HttpSession> {
 public:
  HttpSession(tcp::socket socket, ssl::context& tls, std::shared_ptr<const HttpPipeline> pipeline)
      : _stream(std::move(socket), tls), _pipeline(std::move(pipeline)) {
    boost::system::error_code ec;
    const auto peer = _stream.next_layer().socket().remote_endpoint(ec);
    if (!ec) _peer = peer.address();
  }

  void start() {
    net::dispatch(_stream.get_executor(), [self = shared_from_this()] { self->_handshake(); });
  }

 private:
  Stream _stream;
  std::shared_ptr<const HttpPipeline> _pipeline;
  beast::flat_buffer _buffer;
  std::optional<beast::http::request_parser<beast::http::string_body>> _parser;
  HttpRequest _request;
  net::ip::address _peer;
  std::string _remote;
  std::optional<ClientCertificate> _certificate;

  // The certificate the client presented on the mTLS listener, if any.
  void _read_certificate() {
    SSL* ssl = _stream.native_handle();
    X509* peer = SSL_get1_peer_certificate(ssl);
    if (!peer) return;
    ClientCertificate certificate;
    unsigned char* der = nullptr;
    const int length = i2d_X509(peer, &der);
    if (length > 0) {
      certificate.thumbprint = encoding::base64url(dannan::identity::sha256({der, static_cast<std::size_t>(length)}).bytes);
      OPENSSL_free(der);
    }
    if (BIO* bio = BIO_new(BIO_s_mem())) {
      X509_NAME_print_ex(bio, X509_get_subject_name(peer), 0, XN_FLAG_RFC2253);
      char* data = nullptr;
      const long size = BIO_get_mem_data(bio, &data);
      if (size > 0) certificate.subject.assign(data, static_cast<std::size_t>(size));
      BIO_free(bio);
    }
    certificate.verified = SSL_get_verify_result(ssl) == X509_V_OK;
    X509_free(peer);
    if (!certificate.thumbprint.empty()) _certificate = std::move(certificate);
  }

  void _handshake() {
    _stream.next_layer().expires_after(_pipeline->limits.handshake);

    _stream.async_handshake(ssl::stream_base::server, [self = shared_from_this()](boost::system::error_code ec) {
      if (ec) {
        // Scanners, plaintext clients and old TLS all end here; at debug, so they cannot
        // fill the journal.
        self->_pipeline->logger.debug("TLS handshake from " + self->_peer.to_string() + " failed: " + ec.message());
        return self->_close();
      }
      if (self->_pipeline->client_certificates) self->_read_certificate();
      self->_read();
    });
  }

  void _read() {
    _parser.emplace();
    _parser->body_limit(_pipeline->limits.body_bytes);
    _stream.next_layer().expires_after(_pipeline->limits.idle);

    beast::http::async_read(_stream, _buffer, *_parser, [self = shared_from_this()](boost::system::error_code ec, std::size_t) { self->_on_read(ec); });
  }

  void _on_read(boost::system::error_code ec) {
    if (ec == error::body_limit) {
      auto response = std::make_shared<HttpResponse>(status::payload_too_large, 11);
      write_error(response, status::payload_too_large, "too_large", "the request body is too large");
      response->keep_alive(false);
      return _write(response);
    }

    // The client went, or said nothing for the idle time: nothing to answer.
    if (ec) return _close();

    _request = _parser->release();
    // Only the server says what certificate a client presented: whatever a client sent in
    // these headers is gone before anything reads the request.
    for (const auto* name : {kCertificateThumbprint, kCertificateSubject, kCertificateChain}) {
      while (_request.find(name) != _request.end()) _request.erase(name);
    }
    if (_certificate) {
      _request.set(kCertificateThumbprint, _certificate->thumbprint);
      _request.set(kCertificateSubject, _certificate->subject);
      _request.set(kCertificateChain, _certificate->verified ? "verified" : "unverified");
    }
    _remote = _pipeline->client_address->resolve(_peer, _request);

    _run(0, std::make_shared<HttpResponse>(status::ok, _request.version()));
  }

  // Runs the middleware at index; next(true) moves on, next(false) sends the response. A
  // middleware may call next from another thread, so it comes back to the strand first.
  void _run(std::size_t index, std::shared_ptr<HttpResponse> response) {
    const auto& middlewares = _pipeline->middlewares;

    if (index == middlewares.size()) {
      write_error(response, status::not_found, "not_found", "nothing here");
      return _respond(response);
    }

    auto self = shared_from_this();
    auto next = [self, index, response](bool more) {
      net::dispatch(self->_stream.get_executor(), [self, index, response, more] {
        if (more) return self->_run(index + 1, response);
        self->_respond(response);
      });
    };

    try {
      middlewares[index](_request, _remote, response, std::move(next));
    } catch (const std::exception& e) {
      _pipeline->logger.error(std::string(to_string(_request.method())) + " " + std::string(_request.target()) + " threw: " + e.what());
      write_error(response, status::internal_server_error, "internal", "the server failed to answer");
      _respond(response);
    }
  }

  // The headers every response carries, set last so no middleware can leave one out. A
  // response that set its own, tighter Content-Security-Policy (the sign-in pages) keeps it;
  // every other gets this one.
  void _respond(std::shared_ptr<HttpResponse> response) {
    response->version(_request.version());
    response->set(field::server, "Lugh");
    response->set(field::strict_transport_security, "max-age=63072000; includeSubDomains");
    response->set("X-Content-Type-Options", "nosniff");
    if (response->find("Content-Security-Policy") == response->end())
      response->set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    response->set("Referrer-Policy", "no-referrer");
    response->keep_alive(_request.keep_alive());

    _pipeline->logger.debug(_remote + " " + std::string(to_string(_request.method())) + " " + std::string(_request.target()) + " " +
                            std::to_string(response->result_int()));

    _write(std::move(response));
  }

  void _write(std::shared_ptr<HttpResponse> response) {
    response->prepare_payload();

    beast::http::async_write(_stream, *response, [self = shared_from_this(), response](boost::system::error_code ec, std::size_t) {
      if (ec || !response->keep_alive()) return self->_close();
      self->_read();
    });
  }

  // A TLS close_notify, then the socket; the far end may already have gone, which is fine.
  void _close() {
    _stream.next_layer().expires_after(std::chrono::seconds(5));
    _stream.async_shutdown([self = shared_from_this()](boost::system::error_code) {
      boost::system::error_code ignored;
      self->_stream.next_layer().socket().shutdown(tcp::socket::shutdown_both, ignored);
      self->_stream.next_layer().socket().close(ignored);
    });
  }
};

}  // namespace

HttpServer::HttpServer(std::shared_ptr<dannan::status::LogSink> log, net::io_context& io_context, std::shared_ptr<ssl::context> tls,
                       std::shared_ptr<ClientAddress> client_address, HttpPipeline::Limits limits, bool client_certificates)
    : _logger(std::move(log), "http"),
      _io_context(io_context),
      _acceptor(net::make_strand(io_context)),
      _tls(std::move(tls)),
      _client_address(std::move(client_address)),
      _limits(limits),
      _client_certificates(client_certificates) {}

void HttpServer::middleware_add(HttpMiddleware middleware) { _middlewares.push_back(std::move(middleware)); }

Status HttpServer::listen(const std::string& address, std::uint16_t port) {
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

void HttpServer::start() {
  _pipeline = std::make_shared<const HttpPipeline>(HttpPipeline{_logger, _client_address, _middlewares, _limits, _client_certificates});

  boost::system::error_code ec;
  const auto endpoint = _acceptor.local_endpoint(ec);
  _logger.info("Listening on " + (ec ? std::string("an unknown address") : endpoint.address().to_string() + ":" + std::to_string(endpoint.port())) +
               ", TLS 1.3 only" + (_client_certificates ? ", asking for client certificates" : ""));

  net::dispatch(_acceptor.get_executor(), [self = shared_from_this()] { self->_accept(); });
}

void HttpServer::stop() {
  net::post(_acceptor.get_executor(), [self = shared_from_this()] {
    boost::system::error_code ignored;
    self->_acceptor.close(ignored);
  });
}

std::uint16_t HttpServer::port() const {
  boost::system::error_code ec;
  const auto endpoint = _acceptor.local_endpoint(ec);
  return ec ? 0 : endpoint.port();
}

void HttpServer::_accept() {
  _acceptor.async_accept(net::make_strand(_io_context), [self = shared_from_this()](boost::system::error_code ec, tcp::socket socket) {
    if (ec == net::error::operation_aborted || !self->_acceptor.is_open()) return;

    if (ec) {
      self->_logger.warn("Accept failed: " + ec.message());
    } else {
      std::make_shared<HttpSession>(std::move(socket), *self->_tls, self->_pipeline)->start();
    }

    self->_accept();
  });
}

}  // namespace lugh::http

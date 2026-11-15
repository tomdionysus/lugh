//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/http_server.h"

#include <exception>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "lugh/core/encoding.h"
#include "lugh/http/api_json.h"
#include "lugh/http/client_certificate.h"

namespace lugh::http {

namespace {

using dannan::listen::Stream;

// One connection, its TLS already up: any number of requests on it in turn. Everything runs on
// the stream's strand.
class HttpSession : public std::enable_shared_from_this<HttpSession> {
 public:
  HttpSession(std::shared_ptr<Stream> stream, std::shared_ptr<const HttpPipeline> pipeline)
      : _stream(std::move(stream)), _pipeline(std::move(pipeline)), _peer(_stream->peer().address()) {
    // The certificate the client presented on the mTLS listener, whatever its chain: the routes
    // judge it (RFC 8705).
    if (_pipeline->client_certificates) {
      if (const auto& presented = _stream->client_certificate()) {
        _certificate = ClientCertificate{encoding::base64url(presented->thumbprint), presented->subject, presented->verified};
      }
    }
  }

  void start() { _read(); }

 private:
  std::shared_ptr<Stream> _stream;
  std::shared_ptr<const HttpPipeline> _pipeline;
  net::ip::address _peer;
  beast::flat_buffer _buffer;
  std::optional<beast::http::request_parser<beast::http::string_body>> _parser;
  HttpRequest _request;
  std::string _remote;
  std::optional<ClientCertificate> _certificate;

  void _read() {
    _parser.emplace();
    _parser->body_limit(_pipeline->limits.body_bytes);
    _stream->set_idle(_pipeline->limits.idle);
    beast::http::async_read(*_stream, _buffer, *_parser, [self = shared_from_this()](boost::system::error_code ec, std::size_t) { self->_on_read(ec); });
  }

  void _on_read(boost::system::error_code ec) {
    if (ec == error::body_limit) {
      auto response = std::make_shared<HttpResponse>(status::payload_too_large, 11);
      write_error(response, status::payload_too_large, "too_large", "the request body is too large");
      response->keep_alive(false);
      return _write(response);
    }

    // The client went, said nothing for the idle time, or the connection was closed under the
    // read (operation_aborted): nothing to answer.
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
      net::dispatch(self->_stream->get_executor(), [self, index, response, more] {
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

    beast::http::async_write(*_stream, *response, [self = shared_from_this(), response](boost::system::error_code ec, std::size_t) {
      if (ec || !response->keep_alive()) return self->_close();
      self->_read();
    });
  }

  // A TLS close_notify within the listener's close bound, then the socket; the far end may
  // already have gone, which is fine.
  void _close() { _stream->close(); }
};

}  // namespace

HttpServer::HttpServer(std::shared_ptr<dannan::status::LogSink> log, net::io_context& io_context, std::shared_ptr<dannan::listen::Certificates> certificates,
                       std::shared_ptr<ClientAddress> client_address, HttpPipeline::Limits limits, bool client_certificates)
    : _logger(std::move(log), "http"),
      _io_context(io_context),
      _certificates(std::move(certificates)),
      _client_address(std::move(client_address)),
      _limits(limits),
      _client_certificates(client_certificates) {}

HttpServer::~HttpServer() = default;

void HttpServer::middleware_add(HttpMiddleware middleware) { _middlewares.push_back(std::move(middleware)); }

Status HttpServer::listen(const std::string& address, std::uint16_t port, std::optional<int> inherited) {
  boost::system::error_code ec;
  net::ip::make_address(address, ec);
  if (ec) return Status::failure("not an address to listen on: " + address);

  dannan::listen::ListenerConfig config;
  config.name = _client_certificates ? "mtls" : "https";
  config.host = address;
  config.port = port;
  config.inherited = inherited;
  config.certificates = _certificates;
  config.tls.minimum = dannan::listen::TlsVersion::tls13;
  config.tls.client_certificates = _client_certificates ? dannan::listen::ClientCertificates::optional : dannan::listen::ClientCertificates::never;
  config.tls.alpn = {"http/1.1"};
  config.handshake_timeout = _limits.handshake;
  const auto where = address + ":" + std::to_string(port);
  try {
    _listener = std::make_unique<dannan::listen::StreamListener>(_io_context, std::move(config));
    _listener->start(_io_context.get_executor(), [weak = weak_from_this()](std::shared_ptr<Stream> stream) {
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

void HttpServer::start() {
  auto pipeline = std::make_shared<const HttpPipeline>(HttpPipeline{_logger, _client_address, _middlewares, _limits, _client_certificates});
  {
    dannan::contract::Lock lock(_mutex);
    _pipeline = std::move(pipeline);
  }
  _logger.info("Listening on port " + std::to_string(port()) + ", TLS 1.3 only" + (_client_certificates ? ", asking for client certificates" : ""));
}

void HttpServer::_served(std::shared_ptr<Stream> stream) {
  std::shared_ptr<const HttpPipeline> pipeline;
  {
    dannan::contract::Lock lock(_mutex);
    pipeline = _pipeline;
  }
  // Accepted before start(): nothing is ready to answer it.
  if (!pipeline) return stream->abort();
  std::make_shared<HttpSession>(std::move(stream), std::move(pipeline))->start();
}

void HttpServer::stop() {
  if (_listener) _listener->stop();
}

std::uint16_t HttpServer::port() const { return _listener ? _listener->port() : 0; }

}  // namespace lugh::http

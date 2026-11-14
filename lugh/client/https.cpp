//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/https.h"

#include <openssl/ssl.h>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <memory>
#include <stdexcept>

namespace lugh::client {

namespace {

namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

// One exchange: resolve, connect, handshake, write, read; whichever step fails answers.
class Exchange : public std::enable_shared_from_this<Exchange> {
 public:
  Exchange(net::io_context& io_context, ssl::context& tls, HttpsTarget where, beast::http::verb method, HttpsRequest request, Deadline deadline,
           std::shared_ptr<Completion<Outcome<HttpsResponse>>> answer)
      : _resolver(net::make_strand(io_context)),
        _stream(_resolver.get_executor(), tls),
        _where(std::move(where)),
        _deadline(deadline),
        _answer(std::move(answer)) {
    _request.method(method);
    _request.target(_where.target);
    _request.version(11);
    _request.set(beast::http::field::host, _where.host);
    _request.set(beast::http::field::user_agent, "Lugh");
    for (const auto& [name, value] : request.headers) _request.set(name, value);
    if (!request.content_type.empty()) _request.set(beast::http::field::content_type, request.content_type);
    _request.keep_alive(false);
    _request.body() = std::move(request.body);
    _request.prepare_payload();
  }

  void start() {
    // The name asked for in the handshake, and the name the certificate must carry.
    if (SSL_set_tlsext_host_name(_stream.native_handle(), _where.host.c_str()) != 1) return _failed("the host name cannot be used");
    _stream.set_verify_mode(ssl::verify_peer);
    _stream.set_verify_callback(ssl::host_name_verification(_where.host));
    _resolver.async_resolve(_where.host, _where.port, [self = shared_from_this()](boost::system::error_code resolved, tcp::resolver::results_type found) {
      if (resolved) return self->_failed("the name did not resolve");
      beast::get_lowest_layer(self->_stream).expires_after(self->_deadline);
      beast::get_lowest_layer(self->_stream).async_connect(found, [self](boost::system::error_code connected, const tcp::endpoint&) {
        if (connected) return self->_failed("the connection failed");
        self->_stream.async_handshake(ssl::stream_base::client, [self](boost::system::error_code shaken) {
          if (shaken) return self->_failed("the TLS handshake or the certificate failed");
          beast::http::async_write(self->_stream, self->_request, [self](boost::system::error_code written, std::size_t) {
            if (written) return self->_failed("the request could not be written");
            self->_parser.body_limit(HttpsClient::kMostAnswerBytes);
            beast::http::async_read(self->_stream, self->_buffer, self->_parser, [self](boost::system::error_code answered, std::size_t) {
              if (answered == beast::http::error::body_limit) return self->_failed("the answer is larger than the bound");
              if (answered) return self->_failed("no answer came");
              auto& message = self->_parser.get();
              HttpsResponse response;
              response.status = message.result_int();
              response.content_type = std::string(message[beast::http::field::content_type]);
              response.cache_control = std::string(message[beast::http::field::cache_control]);
              response.etag = std::string(message[beast::http::field::etag]);
              response.body = std::move(message.body());
              self->_answer->finish(Outcome<HttpsResponse>::success(std::move(response)));
            });
          });
        });
      });
    });
  }

 private:
  void _failed(const std::string& why) { _answer->finish(Outcome<HttpsResponse>::failure(Fault::failed, why)); }

  tcp::resolver _resolver;
  beast::ssl_stream<beast::tcp_stream> _stream;
  HttpsTarget _where;
  Deadline _deadline;
  std::shared_ptr<Completion<Outcome<HttpsResponse>>> _answer;
  beast::http::request<beast::http::string_body> _request;
  beast::flat_buffer _buffer;
  beast::http::response_parser<beast::http::string_body> _parser;
};

}  // namespace

std::optional<HttpsTarget> https_target(std::string_view url) {
  constexpr std::string_view kScheme = "https://";
  if (url.rfind(kScheme, 0) != 0) return std::nullopt;
  const auto rest = url.substr(kScheme.size());
  const auto path_at = rest.find_first_of("/?");
  const auto authority = rest.substr(0, path_at);
  HttpsTarget out;
  out.port = "443";
  if (!authority.empty() && authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) return std::nullopt;
    out.host = std::string(authority.substr(1, close - 1));
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') return std::nullopt;
      out.port = std::string(authority.substr(close + 2));
    }
  } else {
    const auto colon = authority.find(':');
    out.host = std::string(authority.substr(0, colon));
    if (colon != std::string_view::npos) out.port = std::string(authority.substr(colon + 1));
  }
  if (out.host.empty() || out.port.empty()) return std::nullopt;
  out.target = path_at == std::string_view::npos ? "/" : std::string(rest.substr(path_at));
  if (out.target.front() == '?') out.target.insert(out.target.begin(), '/');
  return out;
}

HttpsClient::HttpsClient(boost::asio::io_context& io_context, const std::string& ca_path, std::optional<Certificate> certificate)
    : _io_context(io_context), _tls(ssl::context::tls_client) {
  SSL_CTX_set_min_proto_version(_tls.native_handle(), TLS1_2_VERSION);
  boost::system::error_code ec;
  if (ca_path.empty()) {
    _tls.set_default_verify_paths(ec);
  } else {
    _tls.load_verify_file(ca_path, ec);
  }
  if (ec) throw std::runtime_error("cannot load the roots for outbound TLS: " + ec.message());
  _tls.set_verify_mode(ssl::verify_peer);
  if (certificate) {
    _tls.use_certificate_chain_file(certificate->chain_path, ec);
    if (ec) throw std::runtime_error("cannot read the client certificate " + certificate->chain_path + ": " + ec.message());
    _tls.use_private_key_file(certificate->key_path, ssl::context::pem, ec);
    if (ec) throw std::runtime_error("cannot read the client key " + certificate->key_path + ": " + ec.message());
    if (SSL_CTX_check_private_key(_tls.native_handle()) != 1) {
      throw std::runtime_error("the client key " + certificate->key_path + " is not the key of " + certificate->chain_path);
    }
  }
}

void HttpsClient::send(HttpsRequest request, Deadline deadline, Executor executor, Done<Outcome<HttpsResponse>> done) {
  using Answer = Outcome<HttpsResponse>;
  auto answer = Completion<Answer>::start(deadline, executor, std::move(done), [] { return Answer::failure(Fault::failed, "no answer within the deadline"); });
  auto where = https_target(request.url);
  if (!where) return answer->finish(Answer::failure(Fault::failed, "not an https URL"));
  // The methods Lugh's endpoints and API take, and nothing else.
  beast::http::verb method;
  if (request.method == "GET") {
    method = beast::http::verb::get;
  } else if (request.method == "POST") {
    method = beast::http::verb::post;
  } else if (request.method == "PATCH") {
    method = beast::http::verb::patch;
  } else if (request.method == "PUT") {
    method = beast::http::verb::put;
  } else if (request.method == "DELETE") {
    method = beast::http::verb::delete_;
  } else {
    return answer->finish(Answer::failure(Fault::failed, "not a method this client sends: " + request.method));
  }
  std::make_shared<Exchange>(_io_context, _tls, std::move(*where), method, std::move(request), deadline, answer)->start();
}

}  // namespace lugh::client

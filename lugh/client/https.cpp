//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/https.h"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <charconv>
#include <memory>

#include "dannan/listen/certificates.h"
#include "dannan/listen/connector.h"
#include "dannan/listen/stream.h"

namespace lugh::client {

namespace {

namespace beast = boost::beast;
namespace net = boost::asio;
using dannan::listen::Stream;

// One exchange: the connector resolves, connects and checks the server, then a write and a read;
// whichever step fails answers. Everything runs on one strand, the stream's too, and the whole
// exchange is bounded by the caller's deadline: when it passes, the connection is cut.
class Exchange : public std::enable_shared_from_this<Exchange> {
 public:
  Exchange(net::io_context& io_context, HttpsTarget where, uint16_t port, beast::http::verb method, HttpsRequest request, Deadline deadline,
           std::shared_ptr<Completion<Outcome<HttpsResponse>>> answer)
      : _strand(net::make_strand(io_context)), _timer(_strand), _where(std::move(where)), _port(port), _deadline(deadline), _answer(std::move(answer)) {
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

  void start(dannan::listen::StreamConnector& connector, dannan::listen::ClientTls tls) {
    net::dispatch(_strand, [self = shared_from_this()] {
      self->_timer.expires_after(self->_deadline);
      self->_timer.async_wait([self](boost::system::error_code waited) {
        if (waited) return;
        self->_expired = true;
        if (self->_stream) self->_stream->abort();
      });
    });
    connector.connect(_strand, _where.host, _port, std::move(tls), _deadline, [self = shared_from_this()](std::shared_ptr<Stream> stream, std::string why) {
      if (!stream) return self->_failed("the connection failed: " + why);
      if (self->_expired) return stream->abort();
      self->_stream = std::move(stream);
      beast::http::async_write(*self->_stream, self->_request, [self](boost::system::error_code written, std::size_t) {
        if (written) return self->_failed("the request could not be written");
        self->_parser.body_limit(HttpsClient::kMostAnswerBytes);
        beast::http::async_read(*self->_stream, self->_buffer, self->_parser, [self](boost::system::error_code answered, std::size_t) {
          if (answered == beast::http::error::body_limit) return self->_failed("the answer is larger than the bound", Fault::invalid);
          if (answered) return self->_failed("no answer came");
          self->_timer.cancel();
          self->_stream->close();
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
  }

 private:
  // On the strand. A server that cannot be reached, or does not answer, is unavailable.
  void _failed(const std::string& why, Fault fault = Fault::unavailable) {
    _timer.cancel();
    if (_stream) _stream->abort();
    _answer->finish(Outcome<HttpsResponse>::failure(fault, why));
  }

  net::strand<net::io_context::executor_type> _strand;
  net::steady_timer _timer;
  HttpsTarget _where;
  uint16_t _port;
  Deadline _deadline;
  std::shared_ptr<Completion<Outcome<HttpsResponse>>> _answer;
  // On the strand.
  std::shared_ptr<Stream> _stream;
  bool _expired = false;
  beast::http::request<beast::http::string_body> _request;
  beast::flat_buffer _buffer;
  beast::http::response_parser<beast::http::string_body> _parser;
};

// A port from 1 to 65535, written as digits and nothing else.
std::optional<uint16_t> port_number(const std::string& text) {
  unsigned value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size() || value == 0 || value > 65535) return std::nullopt;
  return static_cast<uint16_t>(value);
}

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
    : _io_context(io_context), _trust(std::make_shared<const dannan::listen::ClientTrust>(ca_path)) {
  if (certificate) {
    _certificate = std::make_shared<dannan::listen::Certificates>(dannan::listen::CertificatePaths{certificate->chain_path, certificate->key_path, {}});
  }
  // The exchange's own strand carries each stream, its timer and its callbacks.
  dannan::listen::ConnectorConfig config;
  config.name = "https-out";
  config.strand_per_stream = false;
  _connector = std::make_unique<dannan::listen::StreamConnector>(io_context, std::move(config));
}

HttpsClient::~HttpsClient() = default;

void HttpsClient::send(HttpsRequest request, Deadline deadline, Executor executor, Done<Outcome<HttpsResponse>> done) {
  using Answer = Outcome<HttpsResponse>;
  auto answer =
      Completion<Answer>::start(deadline, executor, std::move(done), [] { return Answer::failure(Fault::timed_out, "no answer within the deadline"); });
  auto where = https_target(request.url);
  const auto port = where ? port_number(where->port) : std::nullopt;
  if (!port) return answer->finish(Answer::failure(Fault::failed, "not an https URL"));
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
  dannan::listen::ClientTls tls;
  tls.trust = _trust;
  tls.certificate = _certificate;
  tls.minimum = dannan::listen::TlsVersion::tls12;
  std::make_shared<Exchange>(_io_context, std::move(*where), *port, method, std::move(request), deadline, answer)->start(*_connector, std::move(tls));
}

}  // namespace lugh::client

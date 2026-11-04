//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/outbound.h"

#include <openssl/ssl.h>

#include <boost/asio/ssl/host_name_verification.hpp>
#include <stdexcept>

namespace lugh::http {

namespace {

using tcp = net::ip::tcp;
constexpr std::size_t kMostAnswerBytes = 64 * 1024;

// One post: resolve, connect, handshake, write, read; whichever step fails answers.
class Post : public std::enable_shared_from_this<Post> {
 public:
  Post(net::io_context& io_context, ssl::context& tls, OutboundTarget where, std::string body, Deadline deadline,
       std::shared_ptr<Completion<Outcome<unsigned>>> answer)
      : _resolver(net::make_strand(io_context)),
        _stream(_resolver.get_executor(), tls),
        _where(std::move(where)),
        _deadline(deadline),
        _answer(std::move(answer)) {
    _request.method(verb::post);
    _request.target(_where.target);
    _request.version(11);
    _request.set(field::host, _where.host);
    _request.set(field::user_agent, "Lugh");
    _request.set(field::content_type, "application/x-www-form-urlencoded");
    _request.keep_alive(false);
    _request.body() = std::move(body);
    _request.prepare_payload();
  }

  void start() {
    // The name asked for in the handshake, and the name the certificate must carry.
    if (SSL_set_tlsext_host_name(_stream.native_handle(), _where.host.c_str()) != 1) return _failed("the host name cannot be used");
    _stream.set_verify_mode(ssl::verify_peer);
    _stream.set_verify_callback(ssl::host_name_verification(_where.host));
    _resolver.async_resolve(_where.host, _where.port, [self = shared_from_this()](boost::system::error_code ec, tcp::resolver::results_type found) {
      if (ec) return self->_failed("the name did not resolve");
      beast::get_lowest_layer(self->_stream).expires_after(self->_deadline);
      beast::get_lowest_layer(self->_stream).async_connect(found, [self](boost::system::error_code ec, const tcp::endpoint&) {
        if (ec) return self->_failed("the connection failed");
        self->_stream.async_handshake(ssl::stream_base::client, [self](boost::system::error_code ec) {
          if (ec) return self->_failed("the TLS handshake or the certificate failed");
          beast::http::async_write(self->_stream, self->_request, [self](boost::system::error_code ec, std::size_t) {
            if (ec) return self->_failed("the request could not be written");
            self->_parser.body_limit(kMostAnswerBytes);
            beast::http::async_read(self->_stream, self->_buffer, self->_parser, [self](boost::system::error_code ec, std::size_t) {
              if (ec) return self->_failed("no answer came");
              self->_answer->finish(Outcome<unsigned>::success(self->_parser.get().result_int()));
            });
          });
        });
      });
    });
  }

 private:
  void _failed(const std::string& why) { _answer->finish(Outcome<unsigned>::failure(Fault::failed, why)); }

  tcp::resolver _resolver;
  beast::ssl_stream<beast::tcp_stream> _stream;
  OutboundTarget _where;
  Deadline _deadline;
  std::shared_ptr<Completion<Outcome<unsigned>>> _answer;
  HttpRequest _request;
  beast::flat_buffer _buffer;
  beast::http::response_parser<beast::http::string_body> _parser;
};

}  // namespace

std::optional<OutboundTarget> outbound_target(std::string_view url) {
  constexpr std::string_view kScheme = "https://";
  if (url.rfind(kScheme, 0) != 0) return std::nullopt;
  const auto rest = url.substr(kScheme.size());
  const auto path_at = rest.find_first_of("/?");
  const auto authority = rest.substr(0, path_at);
  OutboundTarget out;
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

HttpsOutbound::HttpsOutbound(net::io_context& io_context, const std::string& ca_path) : _io_context(io_context), _tls(ssl::context::tls_client) {
  SSL_CTX_set_min_proto_version(_tls.native_handle(), TLS1_2_VERSION);
  boost::system::error_code ec;
  if (ca_path.empty()) {
    _tls.set_default_verify_paths(ec);
  } else {
    _tls.load_verify_file(ca_path, ec);
  }
  if (ec) throw std::runtime_error("cannot load the roots for outbound TLS: " + ec.message());
  _tls.set_verify_mode(ssl::verify_peer);
}

void HttpsOutbound::post_form(std::string url, std::string body, Deadline deadline, Executor executor, Done<Outcome<unsigned>> done) {
  using Answer = Outcome<unsigned>;
  auto answer = Completion<Answer>::start(deadline, executor, std::move(done), [] { return Answer::failure(Fault::failed, "no answer within the deadline"); });
  auto where = outbound_target(url);
  if (!where) return answer->finish(Answer::failure(Fault::failed, "not an https URL"));
  std::make_shared<Post>(_io_context, _tls, std::move(*where), std::move(body), deadline, answer)->start();
}

}  // namespace lugh::http

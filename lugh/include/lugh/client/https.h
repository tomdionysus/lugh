//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"

// HTTPS to another server, as lugh_client and a Lugh node need it: discovery, JWKS, the token
// endpoint, a back-channel logout. The server's certificate and name are always verified, with no
// way to turn that off (docs/architecture.md, "Outbound"); a redirect is an answer, never
// followed; an answer's body is bounded. One request per connection.
namespace lugh::client {

// An https URL taken apart.
struct HttpsTarget {
  std::string host;
  std::string port;
  std::string target;
};

// Nothing for anything that is not an https URL with a host.
std::optional<HttpsTarget> https_target(std::string_view url);

struct HttpsRequest {
  // GET or POST.
  std::string method = "GET";
  std::string url;
  std::vector<std::pair<std::string, std::string>> headers;
  // For a body: its type, and the body.
  std::string content_type;
  std::string body;
};

struct HttpsResponse {
  unsigned status = 0;
  std::string content_type;
  std::string cache_control;
  std::string body;
};

class Https {
 public:
  virtual ~Https() = default;

  // The server's answer, whatever its status; `failed` when none came: not an https URL, the
  // name did not resolve, the connection or the certificate failed, the answer was larger than
  // the bound, or the deadline passed.
  virtual void send(HttpsRequest request, Deadline deadline, Executor executor, Done<Outcome<HttpsResponse>> done) = 0;
};

// The real one, on `io_context`.
class HttpsClient final : public Https {
 public:
  // The largest answer body read.
  static constexpr std::size_t kMostAnswerBytes = 64 * 1024;

  // The roots servers' certificates are checked against: `ca_path` if given, otherwise the
  // system's. Throws std::runtime_error for roots that cannot be read.
  explicit HttpsClient(boost::asio::io_context& io_context, const std::string& ca_path = "");

  void send(HttpsRequest request, Deadline deadline, Executor executor, Done<Outcome<HttpsResponse>> done) override;

 private:
  boost::asio::io_context& _io_context;
  boost::asio::ssl::context _tls;
};

}  // namespace lugh::client

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/http/http_types.h"

namespace lugh::http {

// A form posted to another server, for what Lugh must tell an application (back-channel logout).
class Outbound {
 public:
  virtual ~Outbound() = default;

  // The status the server answered; `failed` when no answer came: the name did not resolve, the
  // connection or the certificate failed, or the deadline passed.
  virtual void post_form(std::string url, std::string body, Deadline deadline, Executor executor, Done<Outcome<unsigned>> done) = 0;
};

// An https URL taken apart.
struct OutboundTarget {
  std::string host;
  std::string port;
  std::string target;
};

// Nothing for anything that is not an https URL with a host.
std::optional<OutboundTarget> outbound_target(std::string_view url);

// The real one: HTTPS, the server's certificate and name always verified, with no way to turn
// that off (docs/architecture.md, "Outbound"); a redirect is an answer, never followed. Runs on
// `io_context`.
class HttpsOutbound : public Outbound {
 public:
  // The roots outbound certificates are checked against: `ca_path` if given, otherwise the
  // system's.
  HttpsOutbound(net::io_context& io_context, const std::string& ca_path = "");

  void post_form(std::string url, std::string body, Deadline deadline, Executor executor, Done<Outcome<unsigned>> done) override;

 private:
  net::io_context& _io_context;
  ssl::context _tls;
};

}  // namespace lugh::http

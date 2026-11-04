//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>

#include "lugh/core/status.h"
#include "lugh/http/http_types.h"

namespace lugh::http {

// The one TLS configuration for every listener, so HTTPS and later LDAPS are set up
// identically: TLS 1.3 and nothing older, the operator's certificate chain and key, no
// compression, no renegotiation. Loaded once at start; a failure is startup's to act on.
class TlsContext {
 public:
  // For the mTLS listener (RFC 8705): a client certificate is asked for, not required, and a
  // connection presenting one that does not chain to `ca_path` (when there is one) still
  // completes: the routes decide what a certificate is good for (lugh/http/client_certificate.h).
  struct ClientCertificates {
    bool request = false;
    std::string ca_path;
  };

  static Result<std::shared_ptr<ssl::context>> server(const std::string& certificate_path, const std::string& key_path);
  static Result<std::shared_ptr<ssl::context>> server(const std::string& certificate_path, const std::string& key_path, ClientCertificates clients);
};

}  // namespace lugh::http

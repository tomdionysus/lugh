//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <string>

#include "lugh/http/http_types.h"

// The certificate a client presented on the mTLS listener (RFC 8705), as the server hands it to
// the routes: in request headers only the server sets. The server removes these headers from
// every request it reads, on every listener, before it sets its own, so a client can never
// claim a certificate it did not present.
namespace lugh::http {

inline constexpr const char* kCertificateThumbprint = "Lugh-Client-Cert-Thumbprint";
inline constexpr const char* kCertificateSubject = "Lugh-Client-Cert-Subject";
inline constexpr const char* kCertificateChain = "Lugh-Client-Cert-Chain";

struct ClientCertificate {
  // The SHA-256 of its DER, base64url: what `x5t#S256` names.
  std::string thumbprint;
  // Its subject DN, as RFC 2253 writes it.
  std::string subject;
  // Whether it chains to the configured client CA (mtls.tls.ca); a certificate that does not
  // is still a key the client holds, good for a thumbprint, never for its subject.
  bool verified = false;
};

inline std::optional<ClientCertificate> client_certificate(const HttpRequest& request) {
  const auto thumbprint = request.find(kCertificateThumbprint);
  if (thumbprint == request.end() || thumbprint->value().empty()) return std::nullopt;
  ClientCertificate out;
  out.thumbprint = std::string(thumbprint->value());
  if (const auto subject = request.find(kCertificateSubject); subject != request.end()) out.subject = std::string(subject->value());
  if (const auto chain = request.find(kCertificateChain); chain != request.end()) out.verified = chain->value() == "verified";
  return out;
}

}  // namespace lugh::http

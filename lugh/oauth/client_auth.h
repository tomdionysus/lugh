//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>

#include "dannan/contract/time_source.h"
#include "lugh/apps/apps.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/http/http_types.h"
#include "lugh/oauth/expiring.h"
#include "lugh/oauth/request.h"

namespace lugh::oauth {

// Which client is calling the token or PAR endpoint, by the method it registered
// (docs/architecture.md, "OAuth profile"):
//
//   client_secret_basic  HTTP Basic, the client_id and secret form-encoded (RFC 6749 2.3.1)
//   private_key_jwt      a client_assertion signed by a key in its JWK Set (RFC 7523, OIDC
//                        Core 9): iss and sub its client_id, aud this server, a jti never seen
//                        before, expiring within ten minutes
//   none                 a public client, PKCE its only proof
//   tls_client_auth      the certificate it presented at the mTLS listener (RFC 8705): by
//                        thumbprint, or by subject when it chains to the client CA
//
// A client presenting more than one method, or one that is not its own, is refused. Every
// refusal is Fault::refused, answered as invalid_client.
class ClientAuthenticator {
 public:
  static constexpr const char* kAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  ClientAuthenticator(std::shared_ptr<apps::Apps> apps, Executor hashing, const dannan::contract::WallClock& wall, const dannan::contract::TimeSource& time,
                      std::string issuer);

  void authenticate(const http::HttpRequest& request, const Parameters& form, Deadline deadline, Executor executor, Done<Outcome<apps::App>> done);

 private:
  std::shared_ptr<apps::Apps> _apps;
  Executor _hashing;
  const dannan::contract::WallClock& _wall;
  std::string _issuer;
  // Assertion jti values seen, kept as long as an assertion can live.
  std::shared_ptr<Expiring<bool>> _seen;
};

}  // namespace lugh::oauth

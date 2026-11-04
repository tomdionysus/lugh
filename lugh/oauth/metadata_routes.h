//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <memory>
#include <string>

#include "lugh/http/router.h"
#include "lugh/tokens/signing_keys.h"

namespace lugh::oauth {

// What an OAuth client or relying party reads before anything else: the public signing keys
// (/oauth2/jwks) and the server's metadata (RFC 8414 at /.well-known/oauth-authorization-server,
// OpenID Connect Discovery 1.0 at /.well-known/openid-configuration). Open routes: they
// reveal only what is public by design.
class MetadataRoutes {
 public:
  struct Settings {
    // The issuer, `iss` in every token: an https URL without a query, fragment or trailing
    // '/'. Empty: no metadata is served, since every URL in it is the issuer's.
    std::string issuer;
    // Whether client_secret_basic is offered (oauth.allow_client_secrets).
    bool allow_client_secrets = false;
    // The mTLS listener's port (oauth.mtls_port); zero for none. With one, the metadata names
    // its endpoints there (RFC 8705 section 5) and offers tls_client_auth.
    std::uint16_t mtls_port = 0;
  };

  // `issuer` on another port: `https://id.example.com/x` on 8444 is
  // `https://id.example.com:8444/x`.
  static std::string on_port(const std::string& issuer, std::uint16_t port);

  MetadataRoutes(std::shared_ptr<const tokens::SigningKeys> keys, Settings settings);

  void register_routes(http::Router& router);

  // The metadata document, the same at both well-known paths.
  boost::json::object metadata() const;

  // Whether `issuer` can be one: https, a host, no query, fragment or trailing '/'.
  static bool issuer_ok(const std::string& issuer);

 private:
  std::shared_ptr<const tokens::SigningKeys> _keys;
  Settings _settings;
};

}  // namespace lugh::oauth

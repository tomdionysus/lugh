//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/metadata_routes.h"

#include "lugh/apps/app.h"
#include "lugh/authn/policy.h"
#include "lugh/http/api_json.h"
#include "lugh/scopes/scope.h"

namespace lugh::oauth {

namespace {

boost::json::array strings(std::initializer_list<const char*> values) {
  boost::json::array out;
  for (const auto* value : values) out.push_back(boost::json::string(value));
  return out;
}

// Published keys change rarely and are announced an hour before they sign: five minutes of
// caching is safe, and spares the server a verifier's every check.
constexpr const char* kKeysCache = "public, max-age=300";

}  // namespace

MetadataRoutes::MetadataRoutes(std::shared_ptr<const tokens::SigningKeys> keys, Settings settings) : _keys(std::move(keys)), _settings(std::move(settings)) {}

bool MetadataRoutes::issuer_ok(const std::string& issuer) {
  return apps::https_uri_ok(issuer) && issuer.find('?') == std::string::npos && issuer.back() != '/';
}

boost::json::object MetadataRoutes::metadata() const {
  const auto& issuer = _settings.issuer;
  boost::json::object out;
  out["issuer"] = issuer;
  // Every endpoint the profile has (docs/architecture.md, "HTTP surface"); P6 brings them in
  // its steps, the authorisation endpoint and the token endpoint first.
  out["authorization_endpoint"] = issuer + "/oauth2/authorize";
  out["token_endpoint"] = issuer + "/oauth2/token";
  out["pushed_authorization_request_endpoint"] = issuer + "/oauth2/par";
  out["device_authorization_endpoint"] = issuer + "/oauth2/device";
  out["userinfo_endpoint"] = issuer + "/oauth2/userinfo";
  out["introspection_endpoint"] = issuer + "/oauth2/introspect";
  out["revocation_endpoint"] = issuer + "/oauth2/revoke";
  out["end_session_endpoint"] = issuer + "/oauth2/logout";
  out["jwks_uri"] = issuer + "/oauth2/jwks";

  boost::json::array scopes;
  for (const auto& scope : scopes::oidc_scopes()) scopes.push_back(boost::json::string(scope));
  out["scopes_supported"] = std::move(scopes);
  out["response_types_supported"] = strings({"code"});
  out["response_modes_supported"] = strings({"query"});
  out["grant_types_supported"] = strings({"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"});
  out["code_challenge_methods_supported"] = strings({"S256"});
  out["subject_types_supported"] = strings({"public"});
  out["id_token_signing_alg_values_supported"] = strings({"ES256", "EdDSA"});
  boost::json::array methods = strings({"private_key_jwt", "tls_client_auth", "none"});
  if (_settings.allow_client_secrets) methods.push_back("client_secret_basic");
  out["token_endpoint_auth_methods_supported"] = methods;
  out["introspection_endpoint_auth_methods_supported"] = methods;
  out["revocation_endpoint_auth_methods_supported"] = methods;
  out["token_endpoint_auth_signing_alg_values_supported"] = strings({"ES256", "EdDSA"});
  out["dpop_signing_alg_values_supported"] = strings({"ES256", "EdDSA"});
  out["tls_client_certificate_bound_access_tokens"] = true;
  out["require_pushed_authorization_requests"] = false;
  out["authorization_response_iss_parameter_supported"] = true;
  out["backchannel_logout_supported"] = true;
  out["backchannel_logout_session_supported"] = true;
  out["frontchannel_logout_supported"] = false;
  out["claims_parameter_supported"] = false;
  out["request_parameter_supported"] = false;
  out["request_uri_parameter_supported"] = true;
  boost::json::array acr;
  for (const auto level : {authn::Assurance::pwd, authn::Assurance::mfa, authn::Assurance::phr}) acr.push_back(boost::json::string(authn::acr(level)));
  out["acr_values_supported"] = std::move(acr);
  out["claims_supported"] = strings({"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid", "name", "given_name", "family_name",
                                     "preferred_username", "email", "groups", "roles"});
  return out;
}

void MetadataRoutes::register_routes(http::Router& router) {
  using http::verb;
  router.add_open(verb::get, "/oauth2/jwks", [keys = _keys](http::RouteContext context) {
    http::write_json(context.response, http::status::ok, keys->jwks());
    context.response->set(http::field::cache_control, kKeysCache);
    context.done();
  });
  if (_settings.issuer.empty()) return;
  for (const auto* path : {"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"}) {
    router.add_open(verb::get, path, [document = metadata()](http::RouteContext context) {
      http::write_json(context.response, http::status::ok, document);
      context.response->set(http::field::cache_control, "public, max-age=3600");
      context.done();
    });
  }
}

}  // namespace lugh::oauth

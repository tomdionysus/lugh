//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/request.h"

#include <algorithm>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/scopes/scope.h"

namespace lugh::oauth {

namespace {

std::string value_of(const Parameters& parameters, const std::string& name) {
  const auto found = parameters.find(name);
  return found == parameters.end() ? std::string() : found->second;
}

// A loopback http URI without its port: `http://127.0.0.1:51004/cb` is `http://127.0.0.1/cb`.
std::optional<std::string> without_loopback_port(std::string_view uri) {
  for (const std::string host : {"http://127.0.0.1", "http://[::1]"}) {
    if (uri.rfind(host, 0) != 0) continue;
    auto rest = uri.substr(host.size());
    if (!rest.empty() && rest.front() == ':') {
      const auto end = rest.find_first_of("/?");
      const auto port = rest.substr(1, end == std::string_view::npos ? std::string_view::npos : end - 1);
      if (port.empty() || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) return std::nullopt;
      rest = end == std::string_view::npos ? std::string_view() : rest.substr(end);
    }
    return host + std::string(rest);
  }
  return std::nullopt;
}

bool unreserved(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'; }

}  // namespace

bool redirect_registered(const apps::App& app, std::string_view uri) {
  if (std::find(app.redirect_uris.begin(), app.redirect_uris.end(), uri) != app.redirect_uris.end()) return true;
  if (app.kind != apps::Kind::native) return false;
  const auto asked = without_loopback_port(uri);
  if (!asked) return false;
  return std::any_of(app.redirect_uris.begin(), app.redirect_uris.end(),
                     [&](const std::string& registered) { return without_loopback_port(registered) == asked; });
}

bool pkce_ok(std::string_view verifier, std::string_view challenge) {
  if (verifier.size() < 43 || verifier.size() > 128 || !std::all_of(verifier.begin(), verifier.end(), unreserved)) return false;
  const auto hash = dannan::identity::sha256({reinterpret_cast<const unsigned char*>(verifier.data()), verifier.size()});
  const auto expected = encoding::base64url(hash.bytes);
  return dannan::identity::constant_time_equal(byte_span(expected), byte_span(challenge));
}

std::variant<AuthorizationRequest, RequestError> check_request(const apps::App& app, const Parameters& parameters) {
  AuthorizationRequest request;
  request.client_id = app.client_id;
  request.redirect_uri = value_of(parameters, "redirect_uri");
  // Until the redirect URI is known to be the client's, nothing goes back to it.
  if (request.redirect_uri.empty()) return RequestError{"invalid_request", "redirect_uri is required", false};
  if (!redirect_registered(app, request.redirect_uri)) return RequestError{"invalid_request", "redirect_uri is not one registered for this application", false};
  if (app.state != apps::State::enabled) return RequestError{"unauthorized_client", "this application is disabled", false};

  request.state = value_of(parameters, "state");
  if (parameters.count("request")) return RequestError{"request_not_supported", "request objects are not accepted; use PAR"};
  if (value_of(parameters, "response_type") != "code") return RequestError{"unsupported_response_type", "response_type is code"};
  if (!(app.grants & apps::kAuthorizationCode)) return RequestError{"unauthorized_client", "this application may not use the code flow"};
  if (const auto mode = value_of(parameters, "response_mode"); !mode.empty() && mode != "query")
    return RequestError{"invalid_request", "response_mode is query"};
  if (request.state.empty()) return RequestError{"invalid_request", "state is required"};

  request.code_challenge = value_of(parameters, "code_challenge");
  if (value_of(parameters, "code_challenge_method") != "S256" || request.code_challenge.size() != 43 ||
      !std::all_of(request.code_challenge.begin(), request.code_challenge.end(), unreserved))
    return RequestError{"invalid_request", "PKCE is required: code_challenge, with code_challenge_method S256"};

  const auto scopes = scopes::split(value_of(parameters, "scope"));
  if (!scopes) return RequestError{"invalid_scope", "scope is a space-separated list of scopes"};
  for (const auto& scope : *scopes) {
    if (std::find(app.scopes.begin(), app.scopes.end(), scope) == app.scopes.end())
      return RequestError{"invalid_scope", "this application may not ask for " + scope};
  }
  request.scopes = scopes::united(*scopes);
  const bool oidc = std::find(request.scopes.begin(), request.scopes.end(), "openid") != request.scopes.end();

  request.nonce = value_of(parameters, "nonce");
  if (oidc && request.nonce.empty()) return RequestError{"invalid_request", "nonce is required with openid"};
  if (request.nonce.size() > 512 || request.state.size() > 1024) return RequestError{"invalid_request", "state or nonce is too long"};

  request.prompt = value_of(parameters, "prompt");
  if (const auto prompts = scopes::split(request.prompt); !prompts) {
    return RequestError{"invalid_request", "prompt is none, login or consent"};
  } else {
    for (const auto& one : *prompts) {
      if (one != "none" && one != "login" && one != "consent") return RequestError{"invalid_request", "prompt is none, login or consent"};
      if (one == "none" && prompts->size() > 1) return RequestError{"invalid_request", "prompt none stands alone"};
    }
  }
  if (const auto age = value_of(parameters, "max_age"); !age.empty()) {
    if (age.size() > 10 || !std::all_of(age.begin(), age.end(), [](char c) { return c >= '0' && c <= '9'; }))
      return RequestError{"invalid_request", "max_age is seconds"};
    request.max_age = std::stoull(age);
  }
  if (const auto acr_values = scopes::split(value_of(parameters, "acr_values"))) {
    for (const auto& one : *acr_values) {
      if (const auto level = authn::assurance_from_acr(one); level && (!request.acr || *level > *request.acr)) request.acr = level;
    }
  }
  return request;
}

std::vector<std::string> granted_scopes(const std::vector<std::string>& asked, const std::vector<std::string>& held,
                                        const std::vector<std::string>& audiences) {
  const auto has = [](const std::vector<std::string>& list, std::string_view item) { return std::find(list.begin(), list.end(), item) != list.end(); };
  std::vector<std::string> out;
  for (const auto& scope : asked) {
    const auto kind = scopes::grantable(scope);
    if (!kind.ok()) continue;
    if (kind.value == scopes::Kind::oidc) {
      out.push_back(scope);
      continue;
    }
    if (!has(held, scope)) continue;
    if (has(audiences, std::string(*scopes::prefix_of(scope)))) out.push_back(scope);
  }
  return scopes::united(std::move(out));
}

}  // namespace lugh::oauth

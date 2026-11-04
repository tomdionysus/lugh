//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "lugh/apps/app.h"
#include "lugh/authn/policy.h"

namespace lugh::oauth {

// An authorisation request (RFC 6749 section 4.1.1, RFC 7636, OIDC Core 3.1.2.1), checked.
struct AuthorizationRequest {
  std::string client_id;
  std::string redirect_uri;
  std::string state;
  std::vector<std::string> scopes;
  std::string code_challenge;
  std::string nonce;
  // "login" forces a sign-in; "none" forbids one; "consent" asks again.
  std::string prompt;
  // Seconds; nothing when not asked.
  std::optional<std::uint64_t> max_age;
  // The least assurance asked for in acr_values, if any it names is Lugh's.
  std::optional<authn::Assurance> acr;
};

// Why a request was refused: an OAuth error code and its description. `redirect` says whether
// the error may go back to the client at its redirect URI, or must be shown on Lugh, because the
// client or the URI could not be trusted (RFC 6749 section 4.1.2.1).
struct RequestError {
  std::string error;
  std::string description;
  bool redirect = true;
};

using Parameters = std::map<std::string, std::string>;

// The request in `parameters` for `app`, checked: the client may use the code flow, the
// redirect URI is one it registered (exactly; for a native app's loopback URI, any port: RFC
// 8252 section 7.3), PKCE S256 is present, every scope is one the app may ask for, `openid`
// comes with a nonce, and nothing Lugh does not offer is asked for.
std::variant<AuthorizationRequest, RequestError> check_request(const apps::App& app, const Parameters& parameters);

// Whether `uri` is one of the app's registered redirect URIs, by RFC 8252's rule for loopback.
bool redirect_registered(const apps::App& app, std::string_view uri);

// Whether `verifier` is a PKCE code verifier (43 to 128 of RFC 7636's characters) whose S256
// challenge is `challenge`.
bool pkce_ok(std::string_view verifier, std::string_view challenge);

// The scopes a token may carry: what was asked for, of what the subject holds (`held`) and the
// OIDC names, and of those only the ones the token's audiences can use (TODO/2026-11-04-oauth.md,
// "What a token carries"). Sorted, each once.
std::vector<std::string> granted_scopes(const std::vector<std::string>& asked, const std::vector<std::string>& held, const std::vector<std::string>& audiences);

}  // namespace lugh::oauth

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "dannan/contract/time_source.h"
#include "dannan/identity/secure_memory.h"
#include "dannan/identity/signing.h"
#include "lugh/client/https.h"
#include "lugh/client/tokens.h"
#include "lugh/client/verifier.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"

// A client of a Lugh issuer (TODO/2026-11-14-p10-plan.md, P10.3): the authorisation code flow with
// PKCE (RFC 6749 section 4.1, RFC 7636, S256 only), optionally pushed first (RFC 9126); the
// browser's return checked for its state, its issuer (RFC 9207) and any error; the code redeemed
// and the ID token verified with its nonce (OpenID Connect Core 1.0, 3.1.3.7); a refresh, whose
// new refresh token replaces the old (Lugh rotates them); and client credentials (RFC 6749
// section 4.4). The client authenticates as it is registered: as a public client, with
// private_key_jwt (RFC 7523, an assertion for the token endpoint living a minute with a fresh jti),
// or with client_secret_basic (RFC 6749 section 2.3.1). Tokens come back as Secrets: they are
// bearer credentials. Every call that waits is in Dannan's callback shape.
namespace lugh::client {

// An issuer's endpoints, as its discovery document names them (OpenID Connect Discovery 1.0).
struct Endpoints {
  std::string issuer;
  std::string authorization;
  std::string token;
  std::string pushed_authorization;
  std::string device_authorization;
  std::string userinfo;
  std::string introspection;
  std::string revocation;
  std::string end_session;

  // The endpoints of `discovery`, which must be `issuer`'s own, with https authorisation and token
  // endpoints; or why not.
  static std::variant<Endpoints, std::string> from_discovery(const boost::json::object& discovery, std::string_view issuer);
};

// Who the client is and how it proves it.
struct ClientIdentity {
  enum class Method { none, private_key_jwt, client_secret_basic };

  std::string client_id;
  Method method = Method::none;
  // private_key_jwt: the key its assertions are signed with, and that key's kid as registered.
  std::shared_ptr<const dannan::identity::SigningKey> key;
  std::string kid;
  // client_secret_basic.
  std::shared_ptr<const dannan::identity::Secret> secret;
  // With a key, every token request carries a DPoP proof by it (RFC 9449), so the tokens are bound
  // to it and good only with proofs by it.
  std::shared_ptr<const dannan::identity::SigningKey> dpop_key;
};

// What the browser is sent to, and what the client keeps until it comes back.
struct AuthorizationRequest {
  std::string url;
  std::string redirect_uri;
  std::string state;
  std::string nonce;
  std::shared_ptr<const dannan::identity::Secret> code_verifier;
};

// What the token endpoint gave (RFC 6749 section 5.1).
struct TokenSet {
  std::shared_ptr<const dannan::identity::Secret> access_token;
  std::string token_type;
  std::uint32_t expires_in = 0;
  std::vector<std::string> scopes;
  // When the client may refresh: the one to use next time, the last one now spent.
  std::shared_ptr<const dannan::identity::Secret> refresh_token;
  // When openid was granted: the ID token verified, and as it came, for a logout's hint.
  std::optional<IdToken> id_token;
  std::string id_token_jwt;
};

// A device authorisation begun (RFC 8628 section 3.2): what the person is shown, and what the
// client polls with.
struct DeviceAuthorization {
  std::shared_ptr<const dannan::identity::Secret> device_code;
  std::string user_code;
  std::string verification_uri;
  std::string verification_uri_complete;
  std::uint32_t expires_in = 0;
  std::uint32_t interval = 5;
};

class DevicePoll;

// A refusal from the issuer reads "<error>: <error_description>", its OAuth error code first, so a
// caller can act on the code.
class OAuthClient {
 public:
  // `https`, `verifier` and `wall` outlive this, and this outlives every call it is asked to make.
  // Throws std::invalid_argument for a client_id that is empty, or a method without what it needs.
  OAuthClient(Endpoints endpoints, ClientIdentity identity, Https& https, const Verifier& verifier, const dannan::contract::WallClock& wall);

  const Endpoints& endpoints() const noexcept { return _endpoints; }

  // A fresh request for `scopes`, back to `redirect_uri`: state, nonce and PKCE verifier made here.
  AuthorizationRequest authorization(const std::string& redirect_uri, const std::vector<std::string>& scopes) const;

  // The same request pushed to the issuer first (RFC 9126): the URL then carries only the
  // client_id and the request_uri the issuer gave.
  void pushed_authorization(const std::string& redirect_uri, const std::vector<std::string>& scopes, Deadline deadline, Executor executor,
                            Done<Outcome<AuthorizationRequest>> done);

  // The query string of the browser's return to the redirect URI, for `request`: the code, or
  // refused (the issuer's error, another state, another issuer) or invalid (no code).
  Outcome<std::string> callback(std::string_view query, const AuthorizationRequest& request) const;

  // The code redeemed for tokens; refused with the issuer's error and description, or an ID
  // token that does not verify; failed when the issuer could not be reached.
  void redeem(const std::string& code, const AuthorizationRequest& request, Deadline deadline, Executor executor, Done<Outcome<TokenSet>> done);

  // New tokens for `refresh_token`, narrowed to `scopes` when some are given.
  void refresh(const dannan::identity::Secret& refresh_token, const std::vector<std::string>& scopes, Deadline deadline, Executor executor,
               Done<Outcome<TokenSet>> done);

  // Tokens for the client itself, for `scopes` (all its client scopes when none).
  void client_credentials(const std::vector<std::string>& scopes, Deadline deadline, Executor executor, Done<Outcome<TokenSet>> done);

  // A device authorisation for `scopes` begun (RFC 8628 section 3.1).
  void device_authorization(const std::vector<std::string>& scopes, Deadline deadline, Executor executor, Done<Outcome<DeviceAuthorization>> done);

  // The tokens once the person has answered (RFC 8628 section 3.4): the token endpoint polled every
  // interval, the first poll an interval after the call, five seconds more after each slow_down,
  // until tokens come or the issuer refuses (access_denied, expired_token), or expires_in passes
  // (refused, expired_token). `time` decides the waits; each poll may take `deadline`.
  void device_tokens(const DeviceAuthorization& started, const dannan::contract::TimeSource& time, Deadline deadline, Executor executor,
                     Done<Outcome<TokenSet>> done);

  // The DPoP header's value for a request to a resource carrying `access_token` (RFC 9449 section
  // 7), by the client's DPoP key; nothing for a client without one. The request then sends
  // `Authorization: DPoP <token>`.
  std::optional<std::string> dpop_proof_for(std::string_view method, std::string_view url, std::string_view access_token) const;

 private:
  friend class DevicePoll;

  // The form's client authentication, and the header it may need.
  void _authenticate(std::vector<std::pair<std::string, std::string>>& form, HttpsRequest& request) const;
  void _token(std::vector<std::pair<std::string, std::string>> form, std::optional<std::string> nonce, Deadline deadline, Executor executor,
              Done<Outcome<TokenSet>> done);

  Endpoints _endpoints;
  ClientIdentity _identity;
  Https& _https;
  const Verifier& _verifier;
  const dannan::contract::WallClock& _wall;
};

}  // namespace lugh::client

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "dannan/contract/time_source.h"
#include "lugh/apps/apps.h"
#include "lugh/directory/directory.h"
#include "lugh/http/router.h"
#include "lugh/oauth/client_auth.h"
#include "lugh/oauth/consents.h"
#include "lugh/oauth/dpop.h"
#include "lugh/oauth/expiring.h"
#include "lugh/oauth/issuer.h"
#include "lugh/oauth/refresh_tokens.h"
#include "lugh/oauth/request.h"
#include "lugh/session/sessions.h"

namespace lugh::oauth {

// An authorisation request waiting on a sign-in or a consent, and when it was asked, so a
// sign-in made after it satisfies prompt=login.
struct Pending {
  AuthorizationRequest request;
  std::uint64_t asked_at = 0;
};

// A pushed authorisation request (RFC 9126): its parameters, and the client that pushed them.
struct Pushed {
  std::string client_id;
  Parameters parameters;
};

// The authorisation code flow (TODO/2026-11-04-oauth.md, "The endpoints"):
//
//   GET  /oauth2/authorize          the request, checked; on to sign-in or consent if needed;
//                                   then the code, back to the client
//   GET  /oauth2/authorize/resume   the same request, after the sign-in it was waiting on
//   GET  /oauth2/consent            what a third-party application asks for, to allow or deny
//   POST /oauth2/consent
//   POST /oauth2/par                a pushed request (RFC 9126)
//   POST /oauth2/token              authorization_code with PKCE, refresh_token, client_credentials
//   POST /oauth2/revoke             a refresh token's family, or an access token (RFC 7009)
//   POST /oauth2/introspect         whether a token is active, and its claims (RFC 7662)
//   GET, POST /oauth2/userinfo      the person's claims, for an access token with openid
//
// A request whose client or redirect URI cannot be trusted is refused on a page of Lugh's and
// never sent anywhere; every other refusal goes back to the client with its state and this
// issuer (RFC 9207). Codes live 60 seconds and are redeemed once, on the node that made them.
class FlowRoutes {
 public:
  struct Parts {
    std::shared_ptr<apps::Apps> apps;
    std::shared_ptr<directory::Directory> directory;
    std::shared_ptr<session::Sessions> sessions;
    std::shared_ptr<Consents> consents;
    std::shared_ptr<TokenIssuer> issuer;
    std::shared_ptr<ClientAuthenticator> clients;
    std::shared_ptr<RefreshTokens> refresh;
    std::shared_ptr<DpopChecker> dpop;
    const dannan::contract::TimeSource* time = nullptr;
    const dannan::contract::WallClock* wall = nullptr;
  };

  explicit FlowRoutes(Parts parts);

  void register_routes(http::Router& router);

  struct Shared;

 private:
  std::shared_ptr<Shared> _shared;
};

}  // namespace lugh::oauth

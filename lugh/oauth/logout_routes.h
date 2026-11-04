//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/apps/apps.h"
#include "lugh/http/router.h"
#include "lugh/oauth/issuer.h"
#include "lugh/session/sessions.h"

namespace lugh::oauth {

// GET, POST /oauth2/logout: OIDC RP-Initiated Logout 1.0.
//
// An id_token_hint of this session's ends it at once, since only the application it was issued to
// holds one. Anything less asks the person first, on a page whose answer carries the session's
// CSRF token. post_logout_redirect_uri must be registered, exactly, by the application the hint or
// client_id names; one that is not is refused on a page of Lugh's and never followed. A hint that
// does not verify, or that disagrees with client_id, is refused the same way.
class LogoutRoutes {
 public:
  LogoutRoutes(std::shared_ptr<apps::Apps> apps, std::shared_ptr<session::Sessions> sessions, std::shared_ptr<const TokenIssuer> issuer);

  void register_routes(http::Router& router);

  struct Shared;

 private:
  std::shared_ptr<Shared> _shared;
};

}  // namespace lugh::oauth

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <optional>

#include "lugh/authn/authenticator.h"
#include "lugh/authn/passwords.h"
#include "lugh/directory/directory.h"
#include "lugh/http/router.h"
#include "lugh/session/sessions.h"

namespace lugh::api {

// Sessions, and the password change that ends them:
//
//   GET    /api/v1/me/sessions           the caller's own sessions
//   DELETE /api/v1/me/sessions/{sid}     one of them ended
//   POST   /api/v1/me/password           {current, new}: a person's own password changed, through
//                                        a session only; every other session of theirs ends
//   GET    /api/v1/users/{id}/sessions   an administrator's view (directory.read)
//   DELETE /api/v1/users/{id}/sessions   every one of them ended (sessions.write)
//
// The session the request came through, if it came through one: never a request carrying a token,
// which is an application acting for the person.
std::optional<session::Session> own_session(session::Sessions& sessions, const http::RouteContext& context);

// A session is shown by its sid, never its handle.
class SessionRoutes {
 public:
  SessionRoutes(std::shared_ptr<session::Sessions> sessions, std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Passwords> passwords,
                std::shared_ptr<authn::Authenticator> authenticator);

  void register_routes(http::Router& router);

 private:
  std::shared_ptr<session::Sessions> _sessions;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<authn::Passwords> _passwords;
  std::shared_ptr<authn::Authenticator> _authenticator;
};

}  // namespace lugh::api

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/authn/authenticator.h"
#include "lugh/directory/directory.h"
#include "lugh/http/router.h"
#include "lugh/session/pre_sessions.h"
#include "lugh/session/sessions.h"

namespace lugh::signin {

// The server-rendered sign-in (TODO/2026-11-04-oauth.md, "The pages"): a password, then a
// second factor; a new password from an enrolment link, then a TOTP factor enrolled and the
// recovery codes shown once; root's first sign-in, which goes from the password to enrolment;
// and signing out. No JavaScript. Every form carries a CSRF token, every value shown is
// escaped, and every page is served under a policy that allows nothing but the stylesheet.
//
//   GET  /signin                 the password form
//   POST /signin                 the password
//   GET  /signin/factor          the second factor: a TOTP code, or a recovery code
//   POST /signin/factor
//   GET  /signin/enrol/totp      a new TOTP secret to add to an authenticator app
//   POST /signin/enrol/totp      a code from it; then the recovery codes, shown once
//   GET  /signin/enrol/{token}   the password form for an enrolment link
//   POST /signin/enrol/{token}
//   GET  /signin/done            signed in, and the sign-out button
//   POST /signout                signs out
//   GET  /signin/style.css
//
// The sign-in itself, its back-off and its audit, are the authenticator's; the pages only
// carry it from one form to the next.
class Pages {
 public:
  Pages(std::shared_ptr<authn::Authenticator> authenticator, std::shared_ptr<directory::Directory> directory, std::shared_ptr<session::Sessions> sessions,
        std::shared_ptr<session::PreSessions> pre_sessions);

  void register_routes(http::Router& router);

  struct Shared;

 private:
  std::shared_ptr<Shared> _shared;
};

}  // namespace lugh::signin

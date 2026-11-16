//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "lugh/authn/authenticator.h"
#include "lugh/authn/challenges.h"
#include "lugh/authn/factors.h"
#include "lugh/directory/directory.h"
#include "lugh/http/router.h"
#include "lugh/session/reauthentications.h"
#include "lugh/session/sessions.h"

namespace lugh::api {

// A person's own factors after enrolment (TODO/2026-11-15-self-factors.md):
//
//   GET    /api/v1/me/factors                         the factors, never a secret
//   POST   /api/v1/me/webauthn/options                {purpose: reauthenticate | register}
//   POST   /api/v1/me/reauthenticate                  {code} or {webauthn: {...}}: opens the window
//   POST   /api/v1/me/factors/totp                    a new TOTP secret, shown once
//   POST   /api/v1/me/factors/totp/{factor}/confirm   {code}: confirms it
//   POST   /api/v1/me/factors/webauthn                {name, challenge, client_data, attestation_object}
//   PATCH  /api/v1/me/factors/{factor}                {name}: a WebAuthn credential renamed
//   DELETE /api/v1/me/factors/{factor}                under the last-factor rule
//   POST   /api/v1/me/factors/recovery                ten new recovery codes, shown once
//
// Only through the person's own signed-in session, never an application holding a token. Every
// change needs the session's re-authentication window open (session/reauthentications.h): 403
// reauthentication_required otherwise. The WebAuthn routes answer 404 where WebAuthn is not
// offered. The changes are audited by the components that make them.
class FactorRoutes {
 public:
  // As the sign-in pages are given it (signin/pages.h), with the one Challenges they share.
  struct WebAuthn {
    std::string rp_id;
    std::vector<std::string> origins;
    std::string rp_name = "Lugh";
    std::shared_ptr<authn::Challenges> challenges;
  };

  // `totp_issuer` is what an authenticator app shows a new TOTP factor under, as at enrolment.
  FactorRoutes(std::shared_ptr<session::Sessions> sessions, std::shared_ptr<session::Reauthentications> windows,
               std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Factors> factors, std::shared_ptr<authn::Authenticator> authenticator,
               std::string totp_issuer);

  // Offers WebAuthn. Before register_routes().
  void webauthn(WebAuthn settings);

  void register_routes(http::Router& router);

  struct Shared;

 private:
  std::shared_ptr<Shared> _shared;
};

}  // namespace lugh::api

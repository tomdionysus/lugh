//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/authn/app_passwords.h"
#include "lugh/http/router.h"

namespace lugh::api {

// App passwords: an administrator's, for any user (/api/v1/users/{id}/app-passwords, under
// lugh:credentials.write to make or revoke one), and the caller's own (/api/v1/me/app-passwords,
// for any caller). A caller making their own is held to their own scopes: an app password is
// never a way to hold more than its owner.
class AppPasswordRoutes {
 public:
  explicit AppPasswordRoutes(std::shared_ptr<authn::AppPasswords> app_passwords);

  void register_routes(http::Router& router);

 private:
  std::shared_ptr<authn::AppPasswords> _app_passwords;
};

}  // namespace lugh::api

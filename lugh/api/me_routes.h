//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/directory/directory.h"
#include "lugh/http/router.h"
#include "lugh/session/sessions.h"

namespace lugh::api {

// /api/v1/me: the caller, as the caller may know it. For a session, also its CSRF token, which
// a page on Lugh's own origin reads here and sends with every change; a page on any other
// origin cannot read it.
class MeRoutes {
 public:
  MeRoutes(std::shared_ptr<directory::Directory> directory, std::shared_ptr<session::Sessions> sessions);

  void register_routes(http::Router& router);

 private:
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<session::Sessions> _sessions;
};

}  // namespace lugh::api

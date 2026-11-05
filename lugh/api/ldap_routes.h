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

namespace lugh::api {

// POST /api/v1/ldap/posix/allocate (directory.write): gives every person and group without a POSIX
// number one, in creation order, in one audited pass: the one way to number what was made before a
// range was configured. Answers {users, groups}, how many of each. Served only when ldap.posix is.
class LdapRoutes {
 public:
  explicit LdapRoutes(std::shared_ptr<directory::Directory> directory);

  void register_routes(http::Router& router);

 private:
  std::shared_ptr<directory::Directory> _directory;
};

}  // namespace lugh::api

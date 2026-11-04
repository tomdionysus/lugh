//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/core/task.h"
#include "lugh/directory/directory.h"
#include "lugh/http/router.h"

namespace lugh::api {

// /api/v1/groups: groups and who is in them.
class GroupRoutes {
 public:
  explicit GroupRoutes(std::shared_ptr<directory::Directory> directory);

  void register_routes(http::Router& router);

 private:
  void _list(http::RouteContext context) const;
  void _create(http::RouteContext context);
  void _get(http::RouteContext context) const;
  void _update(http::RouteContext context);
  void _remove(http::RouteContext context);
  void _members(http::RouteContext context) const;
  void _add_member(http::RouteContext context);
  void _remove_member(http::RouteContext context);

  std::shared_ptr<directory::Directory> _directory;
};

}  // namespace lugh::api

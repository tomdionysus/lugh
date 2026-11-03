//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "core/task.h"
#include "directory/directory.h"
#include "http/router.h"

namespace lugh::api {

// /api/v1/groups: groups and who is in them.
class GroupRoutes {
 public:
  explicit GroupRoutes(std::shared_ptr<directory::Directory> directory);

  void register_routes(http::Router& router);

 private:
  Task<void> _list(http::RouteContext context) const;
  Task<void> _create(http::RouteContext context);
  Task<void> _get(http::RouteContext context) const;
  Task<void> _update(http::RouteContext context);
  Task<void> _remove(http::RouteContext context);
  Task<void> _members(http::RouteContext context) const;
  Task<void> _add_member(http::RouteContext context);
  Task<void> _remove_member(http::RouteContext context);

  std::shared_ptr<directory::Directory> _directory;
};

}  // namespace lugh::api

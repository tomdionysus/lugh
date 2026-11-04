//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/http/router.h"
#include "lugh/scopes/grants.h"

namespace lugh::api {

// /api/v1/scopes, and which scopes each group grants: /api/v1/groups/{id}/scopes.
class ScopeRoutes {
 public:
  explicit ScopeRoutes(std::shared_ptr<scopes::Grants> grants);

  void register_routes(http::Router& router);

 private:
  void _known(http::RouteContext context) const;
  void _group(http::RouteContext context) const;
  void _group_set(http::RouteContext context);

  std::shared_ptr<scopes::Grants> _grants;
};

}  // namespace lugh::api

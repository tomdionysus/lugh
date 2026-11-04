//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <memory>

#include "lugh/apps/apps.h"
#include "lugh/core/outcome.h"
#include "lugh/http/router.h"

namespace lugh::api {

// The JSON for an application, never with a secret or its hash.
boost::json::object app_json(const apps::App& app);

// `body`'s members applied to `app`, each checked for its type and spelling; invalid, naming
// the member, otherwise. `creating` admits what is set only once: kind and scope_prefix.
// What the values mean together is apps::validate()'s.
Outcome<> app_from_json(const boost::json::object& body, bool creating, apps::App& app);

// /api/v1/apps: registering applications, who may use them, their roles and secrets.
class AppRoutes {
 public:
  explicit AppRoutes(std::shared_ptr<apps::Apps> apps);

  void register_routes(http::Router& router);

 private:
  void _list(http::RouteContext context) const;
  void _create(http::RouteContext context);
  void _get(http::RouteContext context) const;
  void _update(http::RouteContext context);
  void _remove(http::RouteContext context);
  void _access(http::RouteContext context, bool allowed);
  void _roles(http::RouteContext context);
  void _secret(http::RouteContext context);

  std::shared_ptr<apps::Apps> _apps;
};

}  // namespace lugh::api

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "http/health_routes.h"

#include <boost/json.hpp>

#include "http/api_json.h"

namespace lugh::http {

void HealthRoutes::register_routes(Router& router) {
  router.add_open(verb::get, "/health", [](RouteContext context) -> Task<void> {
    boost::json::object body;
    body["status"] = "ok";
    write_json(context.response, status::ok, body);
    context.done();
    co_return;
  });

  router.add_open(verb::get, "/ready", [](RouteContext context) -> Task<void> {
    boost::json::object body;
    body["ready"] = true;
    write_json(context.response, status::ok, body);
    context.done();
    co_return;
  });
}

}  // namespace lugh::http

#include "http/health_routes.h"

#include <boost/json.hpp>

#include "http/api_json.h"

namespace lugh::http {

void HealthRoutes::register_routes(Router& router) {
  router.add_open(verb::get, "/health", [](RouteContext context) {
    boost::json::object body;
    body["status"] = "ok";
    write_json(context.response, status::ok, body);
    context.done();
  });

  router.add_open(verb::get, "/ready", [](RouteContext context) {
    boost::json::object body;
    body["ready"] = true;
    write_json(context.response, status::ok, body);
    context.done();
  });
}

}  // namespace lugh::http

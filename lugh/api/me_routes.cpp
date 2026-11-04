//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/me_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/representations.h"
#include "lugh/http/forms.h"

namespace lugh::api {

MeRoutes::MeRoutes(std::shared_ptr<directory::Directory> directory, std::shared_ptr<session::Sessions> sessions)
    : _directory(std::move(directory)), _sessions(std::move(sessions)) {}

void MeRoutes::register_routes(http::Router& router) {
  router.add_authenticated(http::verb::get, "/api/v1/me", [directory = _directory, sessions = _sessions](http::RouteContext context) {
    directory->user(context.caller.id, kRouteDeadline, context.executor, [context, sessions](Outcome<std::optional<directory::User>> user) {
      if (!user.ok()) return answer_fault(context, user);
      if (!user.value) {
        http::write_error(context.response, http::status::not_found, "not_found", "no such user");
        return context.done();
      }
      boost::json::object body;
      body["user"] = user_json(*user.value);
      boost::json::array scopes;
      for (const auto& scope : context.caller.scopes) scopes.push_back(boost::json::string(scope));
      body["scopes"] = std::move(scopes);
      const auto handle = http::cookie(*context.request, session::Sessions::kCookie);
      if (const auto session = handle ? sessions->find(*handle) : std::nullopt) {
        body["session"] = {{"acr", std::string(authn::acr(session->acr))},
                           {"auth_time", timestamp(session->auth_time)},
                           {"csrf_token", session::Sessions::csrf_token(*session)}};
      }
      answer_json(context, http::status::ok, body);
    });
  });
}

}  // namespace lugh::api

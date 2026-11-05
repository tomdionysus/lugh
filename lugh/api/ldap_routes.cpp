//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/ldap_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"

namespace lugh::api {

LdapRoutes::LdapRoutes(std::shared_ptr<directory::Directory> directory) : _directory(std::move(directory)) {}

void LdapRoutes::register_routes(http::Router& router) {
  router.add(http::verb::post, "/api/v1/ldap/posix/allocate", kDirectoryWrite, [directory = _directory](http::RouteContext context) {
    directory->allocate_numbers(actor_of(context), kRouteDeadline, context.executor, [context](Outcome<directory::Numbered> numbered) {
      if (!numbered.ok()) return answer_fault(context, numbered);
      http::write_json(context.response, http::status::ok, boost::json::object{{"users", numbered.value.users}, {"groups", numbered.value.groups}});
      context.done();
    });
  });
}

}  // namespace lugh::api

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/scope_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"

namespace lugh::api {

namespace {

boost::json::array strings(const std::vector<std::string>& values) {
  boost::json::array out;
  for (const auto& value : values) out.push_back(boost::json::string(value));
  return out;
}

void answer_granted(const http::RouteContext& context, const scopes::Granted& granted) {
  boost::json::object body;
  body["scopes"] = strings(granted.scopes);
  http::write_json(context.response, http::status::ok, body);
  context.response->set(http::field::etag, etag(granted.version));
  context.done();
}

}  // namespace

ScopeRoutes::ScopeRoutes(std::shared_ptr<scopes::Grants> grants) : _grants(std::move(grants)) {}

void ScopeRoutes::register_routes(http::Router& router) {
  using http::verb;
  router.add(verb::get, "/api/v1/scopes", kDirectoryRead, [this](http::RouteContext context) { _known(std::move(context)); });
  router.add(verb::get, "/api/v1/groups/{id}/scopes", kDirectoryRead, [this](http::RouteContext context) { _group(std::move(context)); });
  router.add(verb::put, "/api/v1/groups/{id}/scopes", kPoliciesWrite, [this](http::RouteContext context) { _group_set(std::move(context)); });
}

void ScopeRoutes::_known(http::RouteContext context) const {
  boost::json::object body;
  body["lugh"] = strings(scopes::lugh_scopes());
  body["oidc"] = strings(scopes::oidc_scopes());
  answer_json(context, http::status::ok, body);
}

void ScopeRoutes::_group(http::RouteContext context) const {
  _grants->group(context.parameter("id"), kRouteDeadline, context.executor, [context](Outcome<scopes::Granted> granted) {
    if (!granted.ok()) return answer_fault(context, granted);
    answer_granted(context, granted.value);
  });
}

void ScopeRoutes::_group_set(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  const auto body = body_object(context, {"scopes"});
  if (!body) return context.done();
  const auto it = body->find("scopes");
  std::vector<std::string> wanted;
  bool strings_only = it != body->end() && it->value().is_array();
  if (strings_only) {
    for (const auto& one : it->value().as_array()) {
      if (!one.is_string()) {
        strings_only = false;
        break;
      }
      wanted.emplace_back(one.as_string());
    }
  }
  if (!strings_only) {
    http::write_error(context.response, http::status::bad_request, "invalid", "scopes is an array of strings");
    return context.done();
  }
  _grants->group_set(actor_of(context), context.parameter("id"), std::move(wanted), precondition.expected, kRouteDeadline, context.executor,
                     [context](Outcome<scopes::Granted> granted) {
                       if (!granted.ok()) return answer_fault(context, granted);
                       answer_granted(context, granted.value);
                     });
}

}  // namespace lugh::api

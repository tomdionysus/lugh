//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/policy_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"
#include "lugh/core/steps.h"

namespace lugh::api {

namespace {

constexpr const char* kLevels = "acr is urn:lugh:acr:pwd, urn:lugh:acr:mfa or urn:lugh:acr:phr";
constexpr const char* kLevelsOrNull = "acr is urn:lugh:acr:pwd, urn:lugh:acr:mfa or urn:lugh:acr:phr, or null";

// The body's acr: a level, or null where `nullable`. Answers false, having written the 400.
bool acr_member(const http::RouteContext& context, bool nullable, std::optional<authn::Assurance>& out) {
  const auto body = body_object(context, {"acr"});
  if (!body) return false;
  const auto it = body->find("acr");
  if (it != body->end() && it->value().is_null() && nullable) return true;
  if (it == body->end() || !it->value().is_string() || !authn::assurance_from_acr(it->value().as_string())) {
    http::write_error(context.response, http::status::bad_request, "invalid", nullable ? kLevelsOrNull : kLevels);
    return false;
  }
  out = authn::assurance_from_acr(it->value().as_string());
  return true;
}

}  // namespace

PolicyRoutes::PolicyRoutes(std::shared_ptr<authn::Policies> policies, std::shared_ptr<directory::Directory> directory)
    : _policies(std::move(policies)), _directory(std::move(directory)) {}

void PolicyRoutes::register_routes(http::Router& router) {
  using http::verb;
  router.add(verb::get, "/api/v1/policies", kDirectoryRead, [this](http::RouteContext context) { _get(std::move(context)); });
  router.add(verb::put, "/api/v1/policies/global", kPoliciesWrite, [this](http::RouteContext context) { _set_global(std::move(context)); });
  router.add(verb::put, "/api/v1/policies/groups/{id}", kPoliciesWrite, [this](http::RouteContext context) { _set_group(std::move(context)); });
}

void PolicyRoutes::_get(http::RouteContext context) const {
  const auto policies = _policies;
  const auto directory = _directory;
  policies->global(kRouteDeadline, context.executor, [=](Outcome<authn::Assurance> global) {
    if (!global.ok()) return answer_fault(context, global);
    directory->groups(kRouteDeadline, context.executor, [=](Outcome<std::vector<directory::Group>> groups) {
      if (!groups.ok()) return answer_fault(context, groups);
      auto own = std::make_shared<boost::json::array>();
      auto failed = std::make_shared<std::optional<Outcome<>>>();
      in_turn<directory::Group>(
          std::make_shared<std::vector<directory::Group>>(std::move(groups.value)), 0,
          [=](const directory::Group& group, std::function<void()> next) {
            if (*failed) return next();
            policies->group(group.id, kRouteDeadline, context.executor, [=, id = group.id](Outcome<std::optional<authn::Assurance>> level) {
              if (!level.ok()) {
                *failed = Outcome<>::from(level);
              } else if (level.value) {
                boost::json::object one;
                one["group"] = id;
                one["acr"] = std::string(authn::acr(*level.value));
                own->push_back(std::move(one));
              }
              next();
            });
          },
          [=] {
            if (*failed) return answer_fault(context, **failed);
            boost::json::object body;
            body["global"] = std::string(authn::acr(global.value));
            body["groups"] = std::move(*own);
            answer_json(context, http::status::ok, body);
          });
    });
  });
}

void PolicyRoutes::_set_global(http::RouteContext context) {
  std::optional<authn::Assurance> level;
  if (!acr_member(context, false, level)) return context.done();
  _policies->global_set(actor_of(context), *level, kRouteDeadline, context.executor, [this, context](Outcome<> set) {
    if (!set.ok()) return answer_fault(context, set);
    _get(context);
  });
}

void PolicyRoutes::_set_group(http::RouteContext context) {
  std::optional<authn::Assurance> level;
  if (!acr_member(context, true, level)) return context.done();
  _policies->group_set(actor_of(context), context.parameter("id"), level, kRouteDeadline, context.executor, [this, context](Outcome<> set) {
    if (!set.ok()) return answer_fault(context, set);
    _get(context);
  });
}

}  // namespace lugh::api

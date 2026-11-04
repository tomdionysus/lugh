//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/policy_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"
#include "lugh/core/awaited.h"

namespace lugh::api {

namespace {

constexpr const char* kLevels = "acr is urn:lugh:acr:pwd, urn:lugh:acr:mfa or urn:lugh:acr:phr";

// The body's acr: a level, or null where `nullable`. Answers false, having written the 400.
bool acr_member(const http::RouteContext& context, bool nullable, std::optional<authn::Assurance>& out) {
  const auto body = body_object(context, {"acr"});
  if (!body) return false;
  const auto it = body->find("acr");
  if (it != body->end() && it->value().is_null() && nullable) return true;
  if (it == body->end() || !it->value().is_string() || !authn::assurance_from_acr(it->value().as_string())) {
    http::write_error(context.response, http::status::bad_request, "invalid", nullable ? std::string(kLevels) + ", or null" : kLevels);
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
  router.add(verb::get, "/api/v1/policies", kDirectoryRead, [this](http::RouteContext context) -> Task<void> { return _get(std::move(context)); });
  router.add(verb::put, "/api/v1/policies/global", kPoliciesWrite,
             [this](http::RouteContext context) -> Task<void> { return _set_global(std::move(context)); });
  router.add(verb::put, "/api/v1/policies/groups/{id}", kPoliciesWrite,
             [this](http::RouteContext context) -> Task<void> { return _set_group(std::move(context)); });
}

Task<void> PolicyRoutes::_get(http::RouteContext context) const {
  boost::json::object body;
  body["global"] = std::string(authn::acr(co_await awaited_value<authn::Assurance>(
      [&](Executor executor, Done<Outcome<authn::Assurance>> done) { _policies->global(kTransitionDeadline, std::move(executor), std::move(done)); })));
  boost::json::array groups;
  for (const auto& group : co_await awaited_value<std::vector<directory::Group>>([&](Executor executor, Done<Outcome<std::vector<directory::Group>>> done) {
         _directory->groups(kTransitionDeadline, std::move(executor), std::move(done));
       })) {
    const auto level = co_await awaited_value<std::optional<authn::Assurance>>([&](Executor executor, Done<Outcome<std::optional<authn::Assurance>>> done) {
      _policies->group(group.id, kTransitionDeadline, std::move(executor), std::move(done));
    });
    if (!level) continue;
    boost::json::object one;
    one["group"] = group.id;
    one["acr"] = std::string(authn::acr(*level));
    groups.push_back(std::move(one));
  }
  body["groups"] = std::move(groups);
  http::write_json(context.response, http::status::ok, body);
  context.done();
}

Task<void> PolicyRoutes::_set_global(http::RouteContext context) {
  std::optional<authn::Assurance> level;
  if (!acr_member(context, false, level)) {
    context.done();
    co_return;
  }
  const auto set = co_await awaited<Outcome<Nothing>>([&](Executor executor, Done<Outcome<Nothing>> done) {
    _policies->global_set(actor_of(context), *level, kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!set.ok()) {
    write_fault(context.response, set);
    context.done();
    co_return;
  }
  co_await _get(std::move(context));
}

Task<void> PolicyRoutes::_set_group(http::RouteContext context) {
  std::optional<authn::Assurance> level;
  if (!acr_member(context, true, level)) {
    context.done();
    co_return;
  }
  const auto set = co_await awaited<Outcome<Nothing>>([&](Executor executor, Done<Outcome<Nothing>> done) {
    _policies->group_set(actor_of(context), context.parameter("id"), level, kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!set.ok()) {
    write_fault(context.response, set);
    context.done();
    co_return;
  }
  co_await _get(std::move(context));
}

}  // namespace lugh::api

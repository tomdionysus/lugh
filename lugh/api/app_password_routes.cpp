//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/app_password_routes.h"

#include <algorithm>

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"
#include "lugh/scopes/scope.h"

namespace lugh::api {

namespace {

boost::json::array strings(const std::vector<std::string>& values) {
  boost::json::array out;
  for (const auto& value : values) out.push_back(boost::json::string(value));
  return out;
}

boost::json::object info_json(const authn::AppPasswordInfo& info) {
  boost::json::object out;
  out["id"] = info.id;
  out["name"] = info.name;
  out["scopes"] = strings(info.scopes);
  out["networks"] = strings(info.networks);
  out["created_at"] = timestamp(info.created);
  return out;
}

// The body's array of strings, or nothing when absent. False, having written the 400, for
// anything else.
bool strings_member(const http::RouteContext& context, const boost::json::object& body, const char* name, std::vector<std::string>& out) {
  const auto it = body.find(name);
  if (it == body.end()) return true;
  if (!it->value().is_array()) {
    http::write_error(context.response, http::status::bad_request, "invalid", std::string(name) + " must be an array of strings");
    return false;
  }
  for (const auto& one : it->value().as_array()) {
    if (!one.is_string()) {
      http::write_error(context.response, http::status::bad_request, "invalid", std::string(name) + " must be an array of strings");
      return false;
    }
    out.emplace_back(one.as_string());
  }
  return true;
}

using Handler = std::function<void(http::RouteContext, std::string user_id)>;

void list(const std::shared_ptr<authn::AppPasswords>& passwords, http::RouteContext context, std::string user_id) {
  passwords->list(std::move(user_id), kRouteDeadline, context.executor, [context](Outcome<std::vector<authn::AppPasswordInfo>> found) {
    if (!found.ok()) return answer_fault(context, found);
    boost::json::array out;
    for (const auto& one : found.value) out.push_back(info_json(one));
    answer_json(context, http::status::ok, boost::json::object{{"app_passwords", std::move(out)}});
  });
}

// `own`: the caller makes one of their own, and may not give it a scope they do not hold.
void create(const std::shared_ptr<authn::AppPasswords>& passwords, http::RouteContext context, std::string user_id, bool own) {
  const auto body = body_object(context, {"name", "scopes", "networks"});
  std::optional<std::string> name;
  std::vector<std::string> wanted;
  std::vector<std::string> networks;
  if (!body || !string_member(context, *body, "name", name) || !strings_member(context, *body, "scopes", wanted) ||
      !strings_member(context, *body, "networks", networks))
    return context.done();
  if (own) {
    const auto effective = wanted.empty() ? std::vector<std::string>{scopes::kDirectoryRead} : wanted;
    for (const auto& scope : effective) {
      if (!context.caller.has_scope(scope)) {
        http::write_error(context.response, http::status::forbidden, "forbidden", "you do not hold the scope " + scope + " to give it");
        return context.done();
      }
    }
    // An app password that may change anything administers over LDAP, where the router's phr gate
    // does not reach, so a session must be at phr to make one (the maintainer, 2026-11-16). One that only reads
    // stays open at mfa, for mail and the like.
    const bool administers = std::any_of(effective.begin(), effective.end(), [](const std::string& scope) { return scope != scopes::kDirectoryRead; });
    if (administers && context.caller.through_session && context.caller.acr != http::Caller::kAdministerAcr) {
      http::write_error(context.response, http::status::forbidden, "phr_required",
                        "an app password that may change anything needs a sign-in with a passkey or security key");
      return context.done();
    }
  }
  passwords->create(actor_of(context), std::move(user_id), name.value_or(""), std::move(wanted), std::move(networks), kRouteDeadline, context.executor,
                    [context](Outcome<authn::AppPasswords::Made> made) {
                      if (!made.ok()) return answer_fault(context, made);
                      auto shown = info_json(made.value.info);
                      // Shown this once; only its hash is kept.
                      shown["password"] = std::string(secret_text(made.value.password));
                      answer_json(context, http::status::created, shown);
                    });
}

void revoke(const std::shared_ptr<authn::AppPasswords>& passwords, http::RouteContext context, std::string user_id) {
  passwords->revoke(actor_of(context), std::move(user_id), context.parameter("app_password"), kRouteDeadline, context.executor, [context](Outcome<> revoked) {
    if (!revoked.ok()) return answer_fault(context, revoked);
    http::write_no_content(context.response);
    context.done();
  });
}

}  // namespace

AppPasswordRoutes::AppPasswordRoutes(std::shared_ptr<authn::AppPasswords> app_passwords) : _app_passwords(std::move(app_passwords)) {}

void AppPasswordRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto passwords = _app_passwords;
  router.add(verb::get, "/api/v1/users/{id}/app-passwords", kDirectoryRead,
             [passwords](http::RouteContext context) { list(passwords, context, context.parameter("id")); });
  router.add(verb::post, "/api/v1/users/{id}/app-passwords", kCredentialsWrite,
             [passwords](http::RouteContext context) { create(passwords, context, context.parameter("id"), false); });
  router.add(verb::delete_, "/api/v1/users/{id}/app-passwords/{app_password}", kCredentialsWrite,
             [passwords](http::RouteContext context) { revoke(passwords, context, context.parameter("id")); });

  router.add_authenticated(verb::get, "/api/v1/me/app-passwords", [passwords](http::RouteContext context) { list(passwords, context, context.caller.id); });
  router.add_authenticated(verb::post, "/api/v1/me/app-passwords",
                           [passwords](http::RouteContext context) { create(passwords, context, context.caller.id, true); });
  router.add_authenticated(verb::delete_, "/api/v1/me/app-passwords/{app_password}",
                           [passwords](http::RouteContext context) { revoke(passwords, context, context.caller.id); });
}

}  // namespace lugh::api

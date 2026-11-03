//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "api/user_routes.h"

#include "api/api_support.h"
#include "api/representations.h"
#include "api/scopes.h"

namespace lugh::api {

namespace {

void write_user(const http::RouteContext& context, http::status status, const directory::User& user) {
  http::write_json(context.response, status, user_json(user));
  context.response->set(http::field::etag, etag(user.version));
}

}  // namespace

UserRoutes::UserRoutes(std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Factors> factors,
                       std::shared_ptr<authn::Authenticator> authenticator, std::shared_ptr<authn::EnrolmentLinks> links)
    : _directory(std::move(directory)), _factor_store(std::move(factors)), _authenticator(std::move(authenticator)), _links(std::move(links)) {}

void UserRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto bind = [this](auto method) { return [this, method](http::RouteContext context) -> Task<void> { return (this->*method)(std::move(context)); }; };

  router.add(verb::get, "/api/v1/users", kDirectoryRead, bind(&UserRoutes::_list));
  router.add(verb::post, "/api/v1/users", kDirectoryWrite, bind(&UserRoutes::_create));
  router.add(verb::get, "/api/v1/users/{id}", kDirectoryRead, bind(&UserRoutes::_get));
  router.add(verb::patch, "/api/v1/users/{id}", kDirectoryWrite, bind(&UserRoutes::_update));
  router.add(verb::delete_, "/api/v1/users/{id}", kDirectoryWrite, bind(&UserRoutes::_remove));
  router.add(verb::get, "/api/v1/users/{id}/groups", kDirectoryRead, bind(&UserRoutes::_groups));
  router.add(verb::get, "/api/v1/users/{id}/factors", kDirectoryRead, bind(&UserRoutes::_factors));
  router.add(verb::delete_, "/api/v1/users/{id}/factors/{factor}", kCredentialsWrite, bind(&UserRoutes::_remove_factor));
  router.add(verb::post, "/api/v1/users/{id}/factors/reset", kCredentialsWrite, bind(&UserRoutes::_reset_factors));
  router.add(verb::post, "/api/v1/users/{id}/enrolment", kCredentialsWrite, bind(&UserRoutes::_enrolment));
}

Task<void> UserRoutes::_list(http::RouteContext context) const {
  boost::json::array users;
  const auto name = context.query.find("name");
  const auto email = context.query.find("email");
  if (name != context.query.end() || email != context.query.end()) {
    // An exact lookup: none or one.
    const auto found = name != context.query.end() ? co_await _directory->user_by_name(name->second) : co_await _directory->user_by_email(email->second);
    if (found) users.push_back(user_json(*found));
  } else {
    for (const auto& user : co_await _directory->users()) users.push_back(user_json(user));
  }
  boost::json::object body;
  body["users"] = std::move(users);
  http::write_json(context.response, http::status::ok, body);
  context.done();
}

Task<void> UserRoutes::_create(http::RouteContext context) {
  const auto body = body_object(context, {"kind", "name", "email", "display_name"});
  std::optional<std::string> kind, name, email, display;
  if (!body || !string_member(context, *body, "kind", kind) || !string_member(context, *body, "name", name) || !string_member(context, *body, "email", email) ||
      !string_member(context, *body, "display_name", display)) {
    context.done();
    co_return;
  }
  if (kind && *kind != "person" && *kind != "service") {
    http::write_error(context.response, http::status::bad_request, "invalid", "kind is person or service");
    context.done();
    co_return;
  }
  if (!name) {
    http::write_error(context.response, http::status::bad_request, "invalid", "name is required");
    context.done();
    co_return;
  }

  directory::NewUser fresh;
  fresh.kind = kind.value_or("person") == "service" ? directory::Kind::service : directory::Kind::person;
  fresh.name = *name;
  fresh.email = email.value_or("");
  fresh.display_name = display.value_or("");
  const auto made = co_await _directory->create_user(actor_of(context), std::move(fresh));
  if (!made.ok()) {
    write_fault(context.response, made);
    context.done();
    co_return;
  }
  write_user(context, http::status::created, made.value);
  context.response->set(http::field::location, "/api/v1/users/" + made.value.id);
  context.done();
}

Task<void> UserRoutes::_get(http::RouteContext context) const {
  const auto user = co_await _directory->user(context.parameter("id"));
  if (!user) {
    http::write_error(context.response, http::status::not_found, "not_found", "no such user");
    context.done();
    co_return;
  }
  write_user(context, http::status::ok, *user);
  context.done();
}

Task<void> UserRoutes::_update(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) {
    context.done();
    co_return;
  }
  const auto body = body_object(context, {"name", "email", "display_name", "disabled"});
  directory::UserChange change;
  std::optional<bool> disabled;
  if (!body || !string_member(context, *body, "name", change.name) || !string_member(context, *body, "email", change.email) ||
      !string_member(context, *body, "display_name", change.display_name) || !bool_member(context, *body, "disabled", disabled)) {
    context.done();
    co_return;
  }

  const auto id = context.parameter("id");
  const auto actor = actor_of(context);
  auto updated = co_await _directory->update_user(actor, id, std::move(change), precondition.expected);
  if (updated.ok() && disabled) updated = co_await _directory->disable_user(actor, id, *disabled, updated.value.version);
  if (!updated.ok()) {
    write_fault(context.response, updated);
    context.done();
    co_return;
  }
  write_user(context, http::status::ok, updated.value);
  context.done();
}

Task<void> UserRoutes::_remove(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) {
    context.done();
    co_return;
  }
  const auto removed = co_await _directory->remove_user(actor_of(context), context.parameter("id"), precondition.expected);
  if (!removed.ok()) {
    write_fault(context.response, removed);
    context.done();
    co_return;
  }
  http::write_no_content(context.response);
  context.done();
}

Task<void> UserRoutes::_groups(http::RouteContext context) const {
  const auto id = context.parameter("id");
  if (!co_await _directory->user(id)) {
    http::write_error(context.response, http::status::not_found, "not_found", "no such user");
    context.done();
    co_return;
  }
  boost::json::array groups;
  for (const auto& group_id : co_await _directory->groups_of(id)) {
    if (const auto group = co_await _directory->group(group_id)) groups.push_back(group_json(*group));
  }
  boost::json::object body;
  body["groups"] = std::move(groups);
  http::write_json(context.response, http::status::ok, body);
  context.done();
}

Task<void> UserRoutes::_factors(http::RouteContext context) const {
  const auto id = context.parameter("id");
  if (!co_await _directory->user(id)) {
    http::write_error(context.response, http::status::not_found, "not_found", "no such user");
    context.done();
    co_return;
  }
  boost::json::array factors;
  for (const auto& factor : co_await _factor_store->list(id)) factors.push_back(factor_json(factor));
  boost::json::object body;
  body["factors"] = std::move(factors);
  http::write_json(context.response, http::status::ok, body);
  context.done();
}

Task<void> UserRoutes::_remove_factor(http::RouteContext context) {
  const auto id = context.parameter("id");
  const auto key = factor_key(id, context.parameter("factor"));
  if (key.empty() || !co_await _directory->user(id)) {
    http::write_error(context.response, http::status::not_found, "not_found", "no such factor");
    context.done();
    co_return;
  }
  const auto removed = co_await _authenticator->remove_factor(actor_of(context), id, key);
  if (!removed.ok()) {
    write_fault(context.response, removed);
    context.done();
    co_return;
  }
  http::write_no_content(context.response);
  context.done();
}

Task<void> UserRoutes::_reset_factors(http::RouteContext context) {
  if (!body_object(context, {})) {
    context.done();
    co_return;
  }
  const auto reset = co_await _authenticator->reset_factors(actor_of(context), context.parameter("id"));
  if (!reset.ok()) {
    write_fault(context.response, reset);
    context.done();
    co_return;
  }
  http::write_no_content(context.response);
  context.done();
}

Task<void> UserRoutes::_enrolment(http::RouteContext context) {
  if (!body_object(context, {})) {
    context.done();
    co_return;
  }
  const auto issued = co_await _links->issue(actor_of(context), context.parameter("id"));
  if (!issued.ok()) {
    write_fault(context.response, issued);
    context.done();
    co_return;
  }
  const auto link = co_await _links->link(issued.value);

  // The token leaves here once, to the administrator who asked, under Cache-Control:
  // no-store. Only its hash is kept.
  boost::json::object body;
  body["token"] = std::string(issued.value.reveal());
  body["expires_at"] = timestamp(link.ok() ? link.value.expires : 0);
  http::write_json(context.response, http::status::created, body);
  context.done();
}

}  // namespace lugh::api

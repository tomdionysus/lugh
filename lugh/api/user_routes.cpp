//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/user_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/representations.h"
#include "lugh/api/scopes.h"
#include "lugh/core/steps.h"

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
  const auto bind = [this](auto method) { return [this, method](http::RouteContext context) { (this->*method)(std::move(context)); }; };

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

namespace {

void answer_users(const http::RouteContext& context, const std::vector<directory::User>& found) {
  boost::json::array users;
  for (const auto& user : found) users.push_back(user_json(user));
  boost::json::object body;
  body["users"] = std::move(users);
  answer_json(context, http::status::ok, body);
}

void answer_no_such(const http::RouteContext& context, const char* what) {
  http::write_error(context.response, http::status::not_found, "not_found", std::string("no such ") + what);
  context.done();
}

}  // namespace

void UserRoutes::_list(http::RouteContext context) const {
  const auto name = context.query.find("name");
  const auto email = context.query.find("email");
  if (name != context.query.end() || email != context.query.end()) {
    // An exact lookup: none or one.
    const auto one = [context](Outcome<std::optional<directory::User>> found) {
      if (!found.ok()) return answer_fault(context, found);
      answer_users(context, found.value ? std::vector<directory::User>{*found.value} : std::vector<directory::User>{});
    };
    if (name != context.query.end()) return _directory->user_by_name(name->second, kRouteDeadline, context.executor, one);
    return _directory->user_by_email(email->second, kRouteDeadline, context.executor, one);
  }
  _directory->users(kRouteDeadline, context.executor, [context](Outcome<std::vector<directory::User>> found) {
    if (!found.ok()) return answer_fault(context, found);
    answer_users(context, found.value);
  });
}

void UserRoutes::_create(http::RouteContext context) {
  const auto body = body_object(context, {"kind", "name", "email", "display_name"});
  std::optional<std::string> kind, name, email, display;
  if (!body || !string_member(context, *body, "kind", kind) || !string_member(context, *body, "name", name) || !string_member(context, *body, "email", email) ||
      !string_member(context, *body, "display_name", display))
    return context.done();
  if (kind && *kind != "person" && *kind != "service") {
    http::write_error(context.response, http::status::bad_request, "invalid", "kind is person or service");
    return context.done();
  }
  if (!name) {
    http::write_error(context.response, http::status::bad_request, "invalid", "name is required");
    return context.done();
  }

  directory::NewUser fresh;
  fresh.kind = kind.value_or("person") == "service" ? directory::Kind::service : directory::Kind::person;
  fresh.name = *name;
  fresh.email = email.value_or("");
  fresh.display_name = display.value_or("");
  _directory->create_user(actor_of(context), std::move(fresh), kRouteDeadline, context.executor, [context](Outcome<directory::User> made) {
    if (!made.ok()) return answer_fault(context, made);
    write_user(context, http::status::created, made.value);
    context.response->set(http::field::location, "/api/v1/users/" + made.value.id);
    context.done();
  });
}

void UserRoutes::_get(http::RouteContext context) const {
  _directory->user(context.parameter("id"), kRouteDeadline, context.executor, [context](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer_fault(context, user);
    if (!user.value) return answer_no_such(context, "user");
    write_user(context, http::status::ok, *user.value);
    context.done();
  });
}

void UserRoutes::_update(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  const auto body = body_object(context, {"name", "email", "display_name", "disabled"});
  directory::UserChange change;
  std::optional<bool> disabled;
  if (!body || !string_member(context, *body, "name", change.name) || !string_member(context, *body, "email", change.email) ||
      !string_member(context, *body, "display_name", change.display_name) || !bool_member(context, *body, "disabled", disabled))
    return context.done();

  const auto id = context.parameter("id");
  const auto actor = actor_of(context);
  const auto directory = _directory;
  const auto answer = [context](Outcome<directory::User> updated) {
    if (!updated.ok()) return answer_fault(context, updated);
    write_user(context, http::status::ok, updated.value);
    context.done();
  };
  directory->update_user(actor, id, std::move(change), precondition.expected, kRouteDeadline, context.executor, [=](Outcome<directory::User> updated) {
    if (!updated.ok() || !disabled) return answer(std::move(updated));
    directory->disable_user(actor, id, *disabled, updated.value.version, kRouteDeadline, context.executor, answer);
  });
}

void UserRoutes::_remove(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  _directory->remove_user(actor_of(context), context.parameter("id"), precondition.expected, kRouteDeadline, context.executor, [context](Outcome<> removed) {
    if (!removed.ok()) return answer_fault(context, removed);
    http::write_no_content(context.response);
    context.done();
  });
}

void UserRoutes::_groups(http::RouteContext context) const {
  const auto id = context.parameter("id");
  const auto directory = _directory;
  directory->user(id, kRouteDeadline, context.executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer_fault(context, user);
    if (!user.value) return answer_no_such(context, "user");
    directory->groups_of(id, kRouteDeadline, context.executor, [=](Outcome<std::vector<std::string>> ids) {
      if (!ids.ok()) return answer_fault(context, ids);
      auto groups = std::make_shared<boost::json::array>();
      auto failed = std::make_shared<std::optional<Outcome<>>>();
      in_turn<std::string>(
          std::make_shared<std::vector<std::string>>(std::move(ids.value)), 0,
          [=](const std::string& group_id, std::function<void()> next) {
            if (*failed) return next();
            directory->group(group_id, kRouteDeadline, context.executor, [=](Outcome<std::optional<directory::Group>> group) {
              if (!group.ok()) {
                *failed = Outcome<>::from(group);
              } else if (group.value) {
                groups->push_back(group_json(*group.value));
              }
              next();
            });
          },
          [=] {
            if (*failed) return answer_fault(context, **failed);
            boost::json::object body;
            body["groups"] = std::move(*groups);
            answer_json(context, http::status::ok, body);
          });
    });
  });
}

void UserRoutes::_factors(http::RouteContext context) const {
  const auto id = context.parameter("id");
  const auto factors = _factor_store;
  _directory->user(id, kRouteDeadline, context.executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer_fault(context, user);
    if (!user.value) return answer_no_such(context, "user");
    factors->list(id, kRouteDeadline, context.executor, [context](Outcome<std::vector<authn::FactorInfo>> found) {
      if (!found.ok()) return answer_fault(context, found);
      boost::json::array list;
      for (const auto& factor : found.value) list.push_back(factor_json(factor));
      boost::json::object body;
      body["factors"] = std::move(list);
      answer_json(context, http::status::ok, body);
    });
  });
}

void UserRoutes::_remove_factor(http::RouteContext context) {
  const auto id = context.parameter("id");
  const auto key = factor_key(id, context.parameter("factor"));
  if (key.empty()) return answer_no_such(context, "factor");
  const auto authenticator = _authenticator;
  _directory->user(id, kRouteDeadline, context.executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer_fault(context, user);
    if (!user.value) return answer_no_such(context, "factor");
    authenticator->remove_factor(actor_of(context), id, key, kRouteDeadline, context.executor, [context](Outcome<> removed) {
      if (!removed.ok()) return answer_fault(context, removed);
      http::write_no_content(context.response);
      context.done();
    });
  });
}

void UserRoutes::_reset_factors(http::RouteContext context) {
  if (!body_object(context, {})) return context.done();
  _authenticator->reset_factors(actor_of(context), context.parameter("id"), kRouteDeadline, context.executor, [context](Outcome<> reset) {
    if (!reset.ok()) return answer_fault(context, reset);
    http::write_no_content(context.response);
    context.done();
  });
}

void UserRoutes::_enrolment(http::RouteContext context) {
  if (!body_object(context, {})) return context.done();
  const auto links = _links;
  links->issue(actor_of(context), context.parameter("id"), kRouteDeadline, context.executor, [=](Outcome<Secret> issued) {
    if (!issued.ok()) return answer_fault(context, issued);
    // Held where the next step can reach it: a Secret is not copied.
    auto token = std::make_shared<Secret>(std::move(issued.value));
    links->link(Secret(token->reveal()), kRouteDeadline, context.executor, [context, token](Outcome<authn::EnrolmentLinks::Link> link) {
      // The token leaves here once, to the administrator who asked, under Cache-Control:
      // no-store. Only its hash is kept.
      boost::json::object body;
      body["token"] = std::string(secret_text(*token));
      body["expires_at"] = timestamp(link.ok() ? link.value.expires : 0);
      answer_json(context, http::status::created, body);
    });
  });
}

}  // namespace lugh::api

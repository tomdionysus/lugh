//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/group_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/representations.h"
#include "lugh/api/scopes.h"
#include "lugh/core/steps.h"

namespace lugh::api {

namespace {

void write_group(const http::RouteContext& context, http::status status, const directory::Group& group) {
  http::write_json(context.response, status, group_json(group));
  context.response->set(http::field::etag, etag(group.version));
}

}  // namespace

GroupRoutes::GroupRoutes(std::shared_ptr<directory::Directory> directory) : _directory(std::move(directory)) {}

void GroupRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto bind = [this](auto method) { return [this, method](http::RouteContext context) { (this->*method)(std::move(context)); }; };

  router.add(verb::get, "/api/v1/groups", kDirectoryRead, bind(&GroupRoutes::_list));
  router.add(verb::post, "/api/v1/groups", kDirectoryWrite, bind(&GroupRoutes::_create));
  router.add(verb::get, "/api/v1/groups/{id}", kDirectoryRead, bind(&GroupRoutes::_get));
  router.add(verb::patch, "/api/v1/groups/{id}", kDirectoryWrite, bind(&GroupRoutes::_update));
  router.add(verb::delete_, "/api/v1/groups/{id}", kDirectoryWrite, bind(&GroupRoutes::_remove));
  router.add(verb::get, "/api/v1/groups/{id}/members", kDirectoryRead, bind(&GroupRoutes::_members));
  router.add(verb::put, "/api/v1/groups/{id}/members/{user}", kDirectoryWrite, bind(&GroupRoutes::_add_member));
  router.add(verb::delete_, "/api/v1/groups/{id}/members/{user}", kDirectoryWrite, bind(&GroupRoutes::_remove_member));
}

namespace {

void answer_groups(const http::RouteContext& context, const std::vector<directory::Group>& found) {
  boost::json::array groups;
  for (const auto& group : found) groups.push_back(group_json(group));
  boost::json::object body;
  body["groups"] = std::move(groups);
  answer_json(context, http::status::ok, body);
}

}  // namespace

void GroupRoutes::_list(http::RouteContext context) const {
  if (const auto name = context.query.find("name"); name != context.query.end()) {
    return _directory->group_by_name(name->second, kRouteDeadline, context.executor, [context](Outcome<std::optional<directory::Group>> found) {
      if (!found.ok()) return answer_fault(context, found);
      answer_groups(context, found.value ? std::vector<directory::Group>{*found.value} : std::vector<directory::Group>{});
    });
  }
  _directory->groups(kRouteDeadline, context.executor, [context](Outcome<std::vector<directory::Group>> found) {
    if (!found.ok()) return answer_fault(context, found);
    answer_groups(context, found.value);
  });
}

void GroupRoutes::_create(http::RouteContext context) {
  const auto body = body_object(context, {"name", "description"});
  std::optional<std::string> name, description;
  if (!body || !string_member(context, *body, "name", name) || !string_member(context, *body, "description", description)) return context.done();
  if (!name) {
    http::write_error(context.response, http::status::bad_request, "invalid", "name is required");
    return context.done();
  }
  _directory->create_group(actor_of(context), *name, description.value_or(""), kRouteDeadline, context.executor, [context](Outcome<directory::Group> made) {
    if (!made.ok()) return answer_fault(context, made);
    write_group(context, http::status::created, made.value);
    context.response->set(http::field::location, "/api/v1/groups/" + made.value.id);
    context.done();
  });
}

void GroupRoutes::_get(http::RouteContext context) const {
  _directory->group(context.parameter("id"), kRouteDeadline, context.executor, [context](Outcome<std::optional<directory::Group>> group) {
    if (!group.ok()) return answer_fault(context, group);
    if (!group.value) {
      http::write_error(context.response, http::status::not_found, "not_found", "no such group");
      return context.done();
    }
    write_group(context, http::status::ok, *group.value);
    context.done();
  });
}

void GroupRoutes::_update(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  const auto body = body_object(context, {"name", "description"});
  directory::GroupChange change;
  if (!body || !string_member(context, *body, "name", change.name) || !string_member(context, *body, "description", change.description)) return context.done();

  _directory->update_group(actor_of(context), context.parameter("id"), std::move(change), precondition.expected, kRouteDeadline, context.executor,
                           [context](Outcome<directory::Group> updated) {
                             if (!updated.ok()) return answer_fault(context, updated);
                             write_group(context, http::status::ok, updated.value);
                             context.done();
                           });
}

void GroupRoutes::_remove(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  _directory->remove_group(actor_of(context), context.parameter("id"), precondition.expected, kRouteDeadline, context.executor, [context](Outcome<> removed) {
    if (!removed.ok()) return answer_fault(context, removed);
    http::write_no_content(context.response);
    context.done();
  });
}

void GroupRoutes::_members(http::RouteContext context) const {
  const auto id = context.parameter("id");
  const auto directory = _directory;
  directory->group(id, kRouteDeadline, context.executor, [=](Outcome<std::optional<directory::Group>> group) {
    if (!group.ok()) return answer_fault(context, group);
    if (!group.value) {
      http::write_error(context.response, http::status::not_found, "not_found", "no such group");
      return context.done();
    }
    directory->members(id, kRouteDeadline, context.executor, [=](Outcome<std::vector<std::string>> ids) {
      if (!ids.ok()) return answer_fault(context, ids);
      auto members = std::make_shared<boost::json::array>();
      auto failed = std::make_shared<std::optional<Outcome<>>>();
      in_turn<std::string>(
          std::make_shared<std::vector<std::string>>(std::move(ids.value)), 0,
          [=](const std::string& user_id, std::function<void()> next) {
            if (*failed) return next();
            directory->user(user_id, kRouteDeadline, context.executor, [=](Outcome<std::optional<directory::User>> user) {
              if (!user.ok()) {
                *failed = Outcome<>::from(user);
              } else if (user.value) {
                members->push_back(user_json(*user.value));
              }
              next();
            });
          },
          [=] {
            if (*failed) return answer_fault(context, **failed);
            boost::json::object body;
            body["members"] = std::move(*members);
            answer_json(context, http::status::ok, body);
          });
    });
  });
}

// PUT and DELETE on the membership itself: each says what should be true afterwards, so
// a retry is safe and no version is needed.
void GroupRoutes::_add_member(http::RouteContext context) {
  if (!body_object(context, {})) return context.done();
  _directory->add_member(actor_of(context), context.parameter("id"), context.parameter("user"), kRouteDeadline, context.executor, [context](Outcome<> added) {
    if (!added.ok()) return answer_fault(context, added);
    http::write_no_content(context.response);
    context.done();
  });
}

void GroupRoutes::_remove_member(http::RouteContext context) {
  _directory->remove_member(actor_of(context), context.parameter("id"), context.parameter("user"), kRouteDeadline, context.executor,
                            [context](Outcome<> removed) {
                              if (!removed.ok()) return answer_fault(context, removed);
                              http::write_no_content(context.response);
                              context.done();
                            });
}

}  // namespace lugh::api

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
#include "lugh/core/awaited.h"

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
  const auto bind = [this](auto method) { return [this, method](http::RouteContext context) -> Task<void> { return (this->*method)(std::move(context)); }; };

  router.add(verb::get, "/api/v1/groups", kDirectoryRead, bind(&GroupRoutes::_list));
  router.add(verb::post, "/api/v1/groups", kDirectoryWrite, bind(&GroupRoutes::_create));
  router.add(verb::get, "/api/v1/groups/{id}", kDirectoryRead, bind(&GroupRoutes::_get));
  router.add(verb::patch, "/api/v1/groups/{id}", kDirectoryWrite, bind(&GroupRoutes::_update));
  router.add(verb::delete_, "/api/v1/groups/{id}", kDirectoryWrite, bind(&GroupRoutes::_remove));
  router.add(verb::get, "/api/v1/groups/{id}/members", kDirectoryRead, bind(&GroupRoutes::_members));
  router.add(verb::put, "/api/v1/groups/{id}/members/{user}", kDirectoryWrite, bind(&GroupRoutes::_add_member));
  router.add(verb::delete_, "/api/v1/groups/{id}/members/{user}", kDirectoryWrite, bind(&GroupRoutes::_remove_member));
}

Task<void> GroupRoutes::_list(http::RouteContext context) const {
  boost::json::array groups;
  if (const auto name = context.query.find("name"); name != context.query.end()) {
    if (const auto found = co_await awaited_value<std::optional<directory::Group>>([&](Executor executor, Done<Outcome<std::optional<directory::Group>>> done) {
          _directory->group_by_name(name->second, kTransitionDeadline, std::move(executor), std::move(done));
        }))
      groups.push_back(group_json(*found));
  } else {
    for (const auto& group : co_await awaited_value<std::vector<directory::Group>>([&](Executor executor, Done<Outcome<std::vector<directory::Group>>> done) {
           _directory->groups(kTransitionDeadline, std::move(executor), std::move(done));
         }))
      groups.push_back(group_json(group));
  }
  boost::json::object body;
  body["groups"] = std::move(groups);
  http::write_json(context.response, http::status::ok, body);
  context.done();
}

Task<void> GroupRoutes::_create(http::RouteContext context) {
  const auto body = body_object(context, {"name", "description"});
  std::optional<std::string> name, description;
  if (!body || !string_member(context, *body, "name", name) || !string_member(context, *body, "description", description)) {
    context.done();
    co_return;
  }
  if (!name) {
    http::write_error(context.response, http::status::bad_request, "invalid", "name is required");
    context.done();
    co_return;
  }

  const auto made = co_await awaited<Outcome<directory::Group>>([&](Executor executor, Done<Outcome<directory::Group>> done) {
    _directory->create_group(actor_of(context), *name, description.value_or(""), kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!made.ok()) {
    write_fault(context.response, made);
    context.done();
    co_return;
  }
  write_group(context, http::status::created, made.value);
  context.response->set(http::field::location, "/api/v1/groups/" + made.value.id);
  context.done();
}

Task<void> GroupRoutes::_get(http::RouteContext context) const {
  const auto group = co_await awaited_value<std::optional<directory::Group>>([&](Executor executor, Done<Outcome<std::optional<directory::Group>>> done) {
    _directory->group(context.parameter("id"), kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!group) {
    http::write_error(context.response, http::status::not_found, "not_found", "no such group");
    context.done();
    co_return;
  }
  write_group(context, http::status::ok, *group);
  context.done();
}

Task<void> GroupRoutes::_update(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) {
    context.done();
    co_return;
  }
  const auto body = body_object(context, {"name", "description"});
  directory::GroupChange change;
  if (!body || !string_member(context, *body, "name", change.name) || !string_member(context, *body, "description", change.description)) {
    context.done();
    co_return;
  }

  const auto updated = co_await awaited<Outcome<directory::Group>>([&](Executor executor, Done<Outcome<directory::Group>> done) {
    _directory->update_group(actor_of(context), context.parameter("id"), std::move(change), precondition.expected, kTransitionDeadline, std::move(executor),
                             std::move(done));
  });
  if (!updated.ok()) {
    write_fault(context.response, updated);
    context.done();
    co_return;
  }
  write_group(context, http::status::ok, updated.value);
  context.done();
}

Task<void> GroupRoutes::_remove(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) {
    context.done();
    co_return;
  }
  const auto removed = co_await awaited<Outcome<Nothing>>([&](Executor executor, Done<Outcome<Nothing>> done) {
    _directory->remove_group(actor_of(context), context.parameter("id"), precondition.expected, kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!removed.ok()) {
    write_fault(context.response, removed);
    context.done();
    co_return;
  }
  http::write_no_content(context.response);
  context.done();
}

Task<void> GroupRoutes::_members(http::RouteContext context) const {
  const auto id = context.parameter("id");
  if (!co_await awaited_value<std::optional<directory::Group>>([&](Executor executor, Done<Outcome<std::optional<directory::Group>>> done) {
        _directory->group(id, kTransitionDeadline, std::move(executor), std::move(done));
      })) {
    http::write_error(context.response, http::status::not_found, "not_found", "no such group");
    context.done();
    co_return;
  }
  boost::json::array members;
  for (const auto& user_id : co_await awaited_value<std::vector<std::string>>([&](Executor executor, Done<Outcome<std::vector<std::string>>> done) {
         _directory->members(id, kTransitionDeadline, std::move(executor), std::move(done));
       })) {
    if (const auto user = co_await awaited_value<std::optional<directory::User>>([&](Executor executor, Done<Outcome<std::optional<directory::User>>> done) {
          _directory->user(user_id, kTransitionDeadline, std::move(executor), std::move(done));
        }))
      members.push_back(user_json(*user));
  }
  boost::json::object body;
  body["members"] = std::move(members);
  http::write_json(context.response, http::status::ok, body);
  context.done();
}

// PUT and DELETE on the membership itself: each says what should be true afterwards, so
// a retry is safe and no version is needed.
Task<void> GroupRoutes::_add_member(http::RouteContext context) {
  if (!body_object(context, {})) {
    context.done();
    co_return;
  }
  const auto added = co_await awaited<Outcome<Nothing>>([&](Executor executor, Done<Outcome<Nothing>> done) {
    _directory->add_member(actor_of(context), context.parameter("id"), context.parameter("user"), kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!added.ok()) {
    write_fault(context.response, added);
    context.done();
    co_return;
  }
  http::write_no_content(context.response);
  context.done();
}

Task<void> GroupRoutes::_remove_member(http::RouteContext context) {
  const auto removed = co_await awaited<Outcome<Nothing>>([&](Executor executor, Done<Outcome<Nothing>> done) {
    _directory->remove_member(actor_of(context), context.parameter("id"), context.parameter("user"), kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!removed.ok()) {
    write_fault(context.response, removed);
    context.done();
    co_return;
  }
  http::write_no_content(context.response);
  context.done();
}

}  // namespace lugh::api

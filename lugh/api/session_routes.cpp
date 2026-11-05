//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/session_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"
#include "lugh/http/forms.h"

namespace lugh::api {

namespace {

boost::json::object session_json(const session::Session& session, const std::optional<std::string>& current) {
  boost::json::array amr;
  for (const auto& one : session.amr) amr.push_back(boost::json::string(one));
  return boost::json::object{{"sid", session.sid},
                             {"acr", std::string(authn::acr(session.acr))},
                             {"amr", std::move(amr)},
                             {"signed_in_at", timestamp(session.auth_time)},
                             {"last_seen_at", timestamp(session.last_seen)},
                             {"current", current && *current == session.sid}};
}

void answer_sessions(const http::RouteContext& context, const std::vector<session::Session>& sessions, const std::optional<std::string>& current) {
  boost::json::array list;
  for (const auto& one : sessions) list.push_back(session_json(one, current));
  answer_json(context, http::status::ok, boost::json::object{{"sessions", std::move(list)}});
}

// The session the request came through, if it came through one.
std::optional<session::Session> current_session(session::Sessions& sessions, const http::RouteContext& context) {
  if (context.request->find(http::field::authorization) != context.request->end()) return std::nullopt;
  const auto handle = http::cookie(*context.request, session::Sessions::kCookie);
  if (!handle) return std::nullopt;
  return sessions.find(*handle);
}

}  // namespace

SessionRoutes::SessionRoutes(std::shared_ptr<session::Sessions> sessions, std::shared_ptr<directory::Directory> directory,
                             std::shared_ptr<authn::Passwords> passwords, std::shared_ptr<authn::Authenticator> authenticator)
    : _sessions(std::move(sessions)), _directory(std::move(directory)), _passwords(std::move(passwords)), _authenticator(std::move(authenticator)) {}

void SessionRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto sessions = _sessions;
  const auto directory = _directory;
  const auto passwords = _passwords;
  const auto authenticator = _authenticator;

  router.add_authenticated(verb::get, "/api/v1/me/sessions", [sessions](http::RouteContext context) {
    const auto current = current_session(*sessions, context);
    answer_sessions(context, sessions->of_user(context.caller.id), current ? std::optional<std::string>(current->sid) : std::nullopt);
  });

  router.add_authenticated(verb::delete_, "/api/v1/me/sessions/{sid}", [sessions](http::RouteContext context) {
    sessions->end_sid(actor_of(context), context.caller.id, context.parameter("sid"), kRouteDeadline, context.executor, [context](Outcome<> ended) {
      if (!ended.ok()) return answer_fault(context, ended);
      http::write_no_content(context.response);
      context.done();
    });
  });

  router.add_authenticated(verb::post, "/api/v1/me/password", [sessions, directory, passwords, authenticator](http::RouteContext context) {
    // Only the person, through their own session: never an application holding a token.
    const auto session = current_session(*sessions, context);
    if (!session) {
      http::write_error(context.response, http::status::forbidden, "forbidden", "a password is changed through your own signed-in session");
      return context.done();
    }
    const auto body = body_object(context, {"current", "new"});
    std::optional<std::string> current;
    std::optional<std::string> fresh;
    if (!body || !string_member(context, *body, "current", current) || !string_member(context, *body, "new", fresh)) return context.done();
    if (!current || !fresh) {
      http::write_error(context.response, http::status::bad_request, "invalid", "current and new are both needed");
      return context.done();
    }
    const auto user_id = session->user_id;
    const auto keep = session->sid;
    auto replacement = std::make_shared<Secret>(text_secret(*fresh));
    // The current password is checked as a sign-in checks one, with its back-off and audit: a session
    // someone has stolen must not be a faster way to guess it.
    auto given = std::make_shared<Secret>(text_secret(*current));
    directory->user(user_id, kRouteDeadline, context.executor,
                    [context, sessions, passwords, authenticator, user_id, keep, replacement, given](Outcome<std::optional<directory::User>> user) {
                      if (!user.ok()) return answer_fault(context, user);
                      if (!user.value) return answer_fault(context, Outcome<>::failure(Fault::not_found, "no such user"));
                      const auto found = *user.value;
                      authenticator->password(found.name, std::move(*given), context.remote, kRouteDeadline, context.executor,
                                              [context, sessions, passwords, found, user_id, keep, replacement](authn::Step step) {
                                                if (step.kind == authn::Step::Kind::failed) {
                                                  return answer_fault(context, Outcome<>::failure(Fault::failed, "the password could not be checked"));
                                                }
                                                if (step.kind == authn::Step::Kind::wait) {
                                                  http::Router::write_too_many(context.response, step.retry_after);
                                                  return context.done();
                                                }
                                                if (step.kind != authn::Step::Kind::next) {
                                                  http::write_error(context.response, http::status::forbidden, "forbidden",
                                                                    "the current password is not right");
                                                  return context.done();
                                                }
                                                passwords->set(actor_of(context), found, Secret(replacement->reveal()), kRouteDeadline, context.executor,
                                                               [context, sessions, user_id, keep](Outcome<> set) {
                                                                 if (!set.ok()) return answer_fault(context, set);
                                                                 // Someone else holding a session of theirs is shut out with the old password.
                                                                 sessions->end_user(actor_of(context), user_id, keep, "the password was changed",
                                                                                    kRouteDeadline, context.executor, [context](Outcome<std::size_t>) {
                                                                                      http::write_no_content(context.response);
                                                                                      context.done();
                                                                                    });
                                                               });
                                              });
                    });
  });

  router.add(verb::get, "/api/v1/users/{id}/sessions", kDirectoryRead,
             [sessions](http::RouteContext context) { answer_sessions(context, sessions->of_user(context.parameter("id")), std::nullopt); });

  router.add(verb::delete_, "/api/v1/users/{id}/sessions", kSessionsWrite, [sessions](http::RouteContext context) {
    sessions->end_user(actor_of(context), context.parameter("id"), "", "ended by an administrator", kRouteDeadline, context.executor,
                       [context](Outcome<std::size_t> ended) {
                         if (!ended.ok()) return answer_fault(context, ended);
                         answer_json(context, http::status::ok, boost::json::object{{"ended", ended.value}});
                       });
  });
}

}  // namespace lugh::api

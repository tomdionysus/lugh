//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/logout_routes.h"

#include <algorithm>
#include <chrono>
#include <map>
#include <optional>

#include "lugh/http/forms.h"
#include "lugh/oauth/request.h"
#include "lugh/signin/html.h"

namespace lugh::oauth {

struct LogoutRoutes::Shared {
  std::shared_ptr<apps::Apps> apps;
  std::shared_ptr<session::Sessions> sessions;
  std::shared_ptr<const TokenIssuer> issuer;
};

namespace {

using Shared = LogoutRoutes::Shared;
using http::RouteContext;
using http::verb;
using Fields = std::map<std::string, std::string>;

constexpr Deadline kStepDeadline = std::chrono::seconds(15);

std::string value_of(const Fields& fields, const std::string& name) {
  const auto found = fields.find(name);
  return found == fields.end() ? std::string() : found->second;
}

void refused(const RouteContext& context, const std::string& description) {
  signin::write_page(context.response, http::status::bad_request,
                     signin::page("This request cannot be completed", "<p>" + signin::escape(description) + "</p>\n"));
  context.done();
}

// The person is signed out: the cookie cleared, then back to the application if that is known to
// be safe. A form's answer leaves by a page, anything else by a redirect.
void finish(const RouteContext& context, const std::string& target, const std::string& state, bool from_form) {
  context.response->insert(http::field::set_cookie, http::host_cookie(session::Sessions::kCookie, "", 0));
  if (target.empty()) {
    signin::write_page(context.response, http::status::ok, signin::page("Signed out", "<p>You are signed out.</p>\n"));
  } else {
    std::vector<std::pair<std::string, std::string>> parameters;
    if (!state.empty()) parameters.emplace_back("state", state);
    const auto back = with_query(target, parameters);
    from_form ? signin::write_leaving(context.response, back) : signin::write_redirect(context.response, back);
  }
  context.done();
}

void confirm_page(const RouteContext& context, const session::Session& session, const Fields& fields) {
  std::string hidden;
  for (const auto* name : {"id_token_hint", "client_id", "post_logout_redirect_uri", "state"}) {
    const auto value = value_of(fields, name);
    if (!value.empty()) hidden += std::string("<input type=\"hidden\" name=\"") + name + "\" value=\"" + signin::escape(value) + "\">\n";
  }
  signin::write_page(
      context.response, http::status::ok,
      signin::page("Sign out?", "<p>An application asked to sign you out of Lugh.</p>\n<form method=\"post\" action=\"/oauth2/logout\">\n" +
                                    std::string("<input type=\"hidden\" name=\"csrf\" value=\"") + signin::escape(session::Sessions::csrf_token(session)) +
                                    "\">\n" + hidden + "<button type=\"submit\">Sign out</button>\n</form>\n"));
  context.done();
}

// With what is to happen afterwards known safe: ends the session, or asks first.
void decide(const std::shared_ptr<Shared>& shared, const RouteContext& context, const Fields& fields, const std::optional<IdTokenHint>& hint,
            const std::string& target) {
  const auto handle = http::cookie(*context.request, session::Sessions::kCookie);
  const auto session = handle ? shared->sessions->find(*handle) : std::nullopt;
  const auto state = value_of(fields, "state");
  const bool from_form = fields.count("csrf") > 0;
  if (!session) return finish(context, target, state, from_form);
  if (from_form && !session::Sessions::csrf_ok(*session, fields.at("csrf"))) {
    signin::write_page(context.response, http::status::forbidden, signin::page("Not signed out", "<p>That form came from somewhere else.</p>\n"));
    return context.done();
  }
  const bool hinted = hint && !hint->sid.empty() && hint->sid == session->sid && hint->subject == session->user_id;
  if (!from_form && !hinted) return confirm_page(context, *session, fields);
  shared->sessions->end(audit::Actor{session->user_id, context.remote}, *handle, kStepDeadline, context.executor,
                        [context, target, state, from_form](Outcome<> ended) {
                          if (!ended.ok()) {
                            signin::write_page(context.response, http::status::internal_server_error,
                                               signin::page("Not signed out", "<p>Something went wrong. Try again.</p>\n"));
                            return context.done();
                          }
                          finish(context, target, state, from_form);
                        });
}

void logout(const std::shared_ptr<Shared>& shared, const RouteContext& context, const Fields& fields) {
  std::optional<IdTokenHint> hint;
  const auto hint_text = value_of(fields, "id_token_hint");
  if (!hint_text.empty()) {
    hint = shared->issuer->id_token_hint(hint_text);
    if (!hint) return refused(context, "That id_token_hint is not one of Lugh's.");
  }
  auto client_id = value_of(fields, "client_id");
  if (hint) {
    if (!client_id.empty() && client_id != hint->client_id) return refused(context, "That client_id is not the one the id_token_hint was issued to.");
    client_id = hint->client_id;
  }
  const auto target = value_of(fields, "post_logout_redirect_uri");
  if (target.empty()) return decide(shared, context, fields, hint, "");
  if (client_id.empty()) return refused(context, "A post_logout_redirect_uri needs an id_token_hint or a client_id.");
  shared->apps->app(client_id, kStepDeadline, context.executor, [shared, context, fields, hint, target](Outcome<std::optional<apps::App>> app) {
    if (!app.ok() || !app.value) return refused(context, "The application could not be read.");
    const auto& registered = app.value->post_logout_uris;
    if (std::find(registered.begin(), registered.end(), target) == registered.end()) {
      return refused(context, "That post_logout_redirect_uri is not registered for this application.");
    }
    decide(shared, context, fields, hint, target);
  });
}

}  // namespace

LogoutRoutes::LogoutRoutes(std::shared_ptr<apps::Apps> apps, std::shared_ptr<session::Sessions> sessions, std::shared_ptr<const TokenIssuer> issuer)
    : _shared(std::make_shared<Shared>(Shared{std::move(apps), std::move(sessions), std::move(issuer)})) {}

void LogoutRoutes::register_routes(http::Router& router) {
  auto shared = _shared;
  router.add_open(verb::get, "/oauth2/logout", [shared](RouteContext context) {
    Fields fields;
    for (const auto& [name, value] : context.query) {
      // A form's token never comes in a URL.
      if (name != "csrf") fields[name] = value;
    }
    logout(shared, context, fields);
  });
  router.add_open(verb::post, "/oauth2/logout", [shared](RouteContext context) {
    const auto form = http::parse_form(context.body());
    if (!form) return refused(context, "The body is a form, one value per name.");
    Fields fields;
    for (const auto& [name, value] : *form) fields[name] = value;
    logout(shared, context, fields);
  });
}

}  // namespace lugh::oauth

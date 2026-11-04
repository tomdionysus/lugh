//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/flow_routes.h"

#include <algorithm>

#include "dannan/encoding/percent.h"
#include "lugh/http/api_json.h"
#include "lugh/http/forms.h"
#include "lugh/scopes/scope.h"
#include "lugh/signin/html.h"

namespace lugh::oauth {

using http::RouteContext;

struct FlowRoutes::Shared {
  Parts parts;
  Expiring<Pending> pending;
  Expiring<CodeGrant> codes;
  Expiring<Pushed> pushed;

  explicit Shared(Parts given)
      : parts(std::move(given)),
        pending(*parts.time, std::chrono::minutes(15)),
        codes(*parts.time, std::chrono::seconds(60)),
        pushed(*parts.time, std::chrono::seconds(60)) {}

  std::uint64_t now() const { return parts.wall->unix_ms() / 1000; }
};

namespace {

using Shared = FlowRoutes::Shared;

constexpr Deadline kStepDeadline = std::chrono::seconds(15);
constexpr const char* kRequestUriPrefix = "urn:ietf:params:oauth:request_uri:";

bool has(const std::vector<std::string>& list, std::string_view item) { return std::find(list.begin(), list.end(), item) != list.end(); }

std::string encoded(std::string_view text) { return dannan::encoding::percent_encode(text, dannan::encoding::PercentSet::unreserved()); }

// `uri` with `parameters` added to its query.
std::string with_query(const std::string& uri, const std::vector<std::pair<std::string, std::string>>& parameters) {
  std::string out = uri;
  char joiner = uri.find('?') == std::string::npos ? '?' : '&';
  for (const auto& [name, value] : parameters) {
    out += joiner + encoded(name) + "=" + encoded(value);
    joiner = '&';
  }
  return out;
}

void error_page(const RouteContext& context, const std::string& description) {
  signin::write_page(context.response, http::status::bad_request,
                     signin::page("This request cannot be completed", "<p>" + signin::escape(description) +
                                                                          "</p>\n<p class=\"muted\">Lugh will not send you back to the application that "
                                                                          "asked, because it could not tell where that is safe.</p>\n"));
  context.done();
}

// An error sent back to the client (RFC 6749 section 4.1.2.1, RFC 9207's iss).
void error_back(const Shared& shared, const RouteContext& context, const AuthorizationRequest& request, const std::string& error,
                const std::string& description) {
  std::vector<std::pair<std::string, std::string>> parameters{{"error", error}, {"error_description", description}};
  if (!request.state.empty()) parameters.emplace_back("state", request.state);
  parameters.emplace_back("iss", shared.parts.issuer->issuer());
  signin::write_redirect(context.response, with_query(request.redirect_uri, parameters));
  context.done();
}

// The code, back to the client.
void issue_code(const std::shared_ptr<Shared>& shared, const RouteContext& context, const AuthorizationRequest& request, const session::Session& session) {
  CodeGrant grant{request.client_id, request.redirect_uri, request.scopes, request.code_challenge, request.nonce, session.user_id,
                  session.sid,       session.acr,          session.amr,    session.auth_time};
  const auto code = shared->codes.put(std::move(grant));
  std::vector<std::pair<std::string, std::string>> parameters{{"code", code}};
  if (!request.state.empty()) parameters.emplace_back("state", request.state);
  parameters.emplace_back("iss", shared->parts.issuer->issuer());
  signin::write_redirect(context.response, with_query(request.redirect_uri, parameters));
  context.done();
}

// What a scope lets the application do, for the consent page.
std::string meaning(const std::string& scope) {
  if (scope == "openid") return "Know who you are";
  if (scope == "profile") return "See your name";
  if (scope == "email") return "See your email address";
  if (scope == "groups") return "See which groups you are in";
  if (scope == "offline_access") return "Stay signed in when you are not using it";
  return "Use " + scope;
}

std::optional<session::Session> session_of(const Shared& shared, const RouteContext& context) {
  const auto handle = http::cookie(*context.request, session::Sessions::kCookie);
  return handle ? shared.parts.sessions->find(*handle) : std::nullopt;
}

// Where an authorisation request goes next: to sign in, to consent, or back with its code.
void decide(const std::shared_ptr<Shared>& shared, const RouteContext& context, Pending pending) {
  const auto& request = pending.request;
  shared->parts.apps->app(request.client_id, kStepDeadline, context.executor, [shared, context, pending](Outcome<std::optional<apps::App>> found) {
    const auto& request = pending.request;
    if (!found.ok()) return error_back(*shared, context, request, "server_error", "the application could not be read");
    if (!found.value || found.value->state != apps::State::enabled) return error_page(context, "This application is not allowed to sign anyone in.");
    const auto app = *found.value;

    // How sure Lugh must be: the application's least, and what this request asks for.
    auto required = authn::Assurance::pwd;
    if (const auto level = authn::assurance_from_acr(app.acr)) required = std::max(required, *level);
    if (request.acr) required = std::max(required, *request.acr);
    // Nobody reaches phr before WebAuthn (P11): refused rather than given less.
    if (required == authn::Assurance::phr)
      return error_back(*shared, context, request, "unmet_authentication_requirements", "this application needs a phishing-resistant sign-in");

    const auto session = session_of(*shared, context);
    const auto now = shared->now();
    const bool login_asked = request.prompt.find("login") != std::string::npos;
    const auto max_age = request.max_age ? request.max_age : (app.max_age ? std::optional<std::uint64_t>(app.max_age) : std::nullopt);
    const bool needs_sign_in =
        !session || session->acr < required || (login_asked && session->auth_time < pending.asked_at) || (max_age && now > session->auth_time + *max_age);
    if (needs_sign_in) {
      if (request.prompt == "none") return error_back(*shared, context, request, "login_required", "signing in is needed");
      const auto id = shared->pending.put(pending);
      signin::write_redirect(context.response, "/signin?continue=" + encoded(id));
      return context.done();
    }

    // Who may use it: its groups' members, and nobody else.
    shared->parts.directory->groups_of(
        session->user_id, kStepDeadline, context.executor, [shared, context, pending, app, session](Outcome<std::vector<std::string>> groups) {
          const auto& request = pending.request;
          if (!groups.ok()) return error_back(*shared, context, request, "server_error", "your groups could not be read");
          const bool allowed = std::any_of(app.access.begin(), app.access.end(), [&](const std::string& group) { return has(groups.value, group); });
          if (!allowed) return error_back(*shared, context, request, "access_denied", "you are not allowed to use this application");
          if (app.first_party) return issue_code(shared, context, request, *session);

          shared->parts.consents->scopes(
              session->user_id, app.client_id, kStepDeadline, context.executor, [shared, context, pending, session](Outcome<std::vector<std::string>> given) {
                const auto& request = pending.request;
                if (!given.ok()) return error_back(*shared, context, request, "server_error", "consent could not be read");
                const bool covered =
                    std::all_of(request.scopes.begin(), request.scopes.end(), [&](const std::string& scope) { return has(given.value, scope); });
                if (covered && request.prompt.find("consent") == std::string::npos) {
                  return issue_code(shared, context, request, *session);
                }
                if (request.prompt == "none") return error_back(*shared, context, request, "consent_required", "consent is needed");
                const auto id = shared->pending.put(pending);
                signin::write_redirect(context.response, "/oauth2/consent?id=" + encoded(id));
                context.done();
              });
        });
  });
}

void authorize(const std::shared_ptr<Shared>& shared, RouteContext context) {
  auto parameters = Parameters(context.query.begin(), context.query.end());
  const auto client_id = parameters.count("client_id") ? parameters.at("client_id") : std::string();
  if (client_id.empty()) return error_page(context, "The request does not say which application it is for.");

  // A pushed request stands in for the parameters (RFC 9126 section 4).
  if (const auto uri = parameters.find("request_uri"); uri != parameters.end()) {
    if (uri->second.rfind(kRequestUriPrefix, 0) != 0) return error_page(context, "That request_uri is not one of Lugh's.");
    const auto pushed = shared->pushed.take(std::string_view(uri->second).substr(std::string_view(kRequestUriPrefix).size()));
    if (!pushed || pushed->client_id != client_id) return error_page(context, "That pushed request has expired, been used, or is another application's.");
    parameters = pushed->parameters;
  }

  shared->parts.apps->app(client_id, kStepDeadline, context.executor, [shared, context, parameters](Outcome<std::optional<apps::App>> found) {
    if (!found.ok()) return error_page(context, "The application could not be read. Try again.");
    if (!found.value) return error_page(context, "Lugh does not know this application.");
    auto checked = check_request(*found.value, parameters);
    if (const auto* error = std::get_if<RequestError>(&checked)) {
      if (!error->redirect) return error_page(context, error->description);
      AuthorizationRequest back;
      back.redirect_uri = parameters.at("redirect_uri");
      back.state = parameters.count("state") ? parameters.at("state") : std::string();
      return error_back(*shared, context, back, error->error, error->description);
    }
    decide(shared, context, Pending{std::get<AuthorizationRequest>(std::move(checked)), shared->now()});
  });
}

// The token endpoint's answers (RFC 6749 section 5).
void token_error(const RouteContext& context, http::status status, const std::string& error, const std::string& description) {
  http::write_json(context.response, status, boost::json::object{{"error", error}, {"error_description", description}});
  context.response->set(http::field::pragma, "no-cache");
  if (status == http::status::unauthorized) context.response->set(http::field::www_authenticate, "Basic realm=\"lugh\"");
  context.done();
}

void token_answer(const RouteContext& context, const Issued& issued) {
  boost::json::object body{
      {"access_token", issued.access_token}, {"token_type", "Bearer"}, {"expires_in", issued.expires_in}, {"scope", scopes::join(issued.scopes)}};
  if (issued.id_token) body["id_token"] = *issued.id_token;
  http::write_json(context.response, http::status::ok, body);
  context.response->set(http::field::pragma, "no-cache");
  context.done();
}

void token(const std::shared_ptr<Shared>& shared, RouteContext context) {
  const auto form = http::parse_form(context.body());
  if (!form) return token_error(context, http::status::bad_request, "invalid_request", "the body is a form, one value per name");
  const auto grant_type = form->count("grant_type") ? form->at("grant_type") : std::string();
  shared->parts.clients->authenticate(
      *context.request, *form, kStepDeadline, context.executor, [shared, context, form = *form, grant_type](Outcome<apps::App> client) {
        if (!client.ok()) {
          if (client.fault == Fault::refused) return token_error(context, http::status::unauthorized, "invalid_client", client.message);
          return token_error(context, http::status::internal_server_error, "server_error", "the client could not be checked");
        }
        const auto app = client.value;
        if (app.sender != apps::SenderConstraint::none)
          return token_error(context, http::status::bad_request, "invalid_request", "sender-constrained tokens (DPoP, mTLS) arrive with O8");
        const auto value_of = [&](const char* name) { return form.count(name) ? form.at(name) : std::string(); };

        if (grant_type == "authorization_code") {
          if (!(app.grants & apps::kAuthorizationCode))
            return token_error(context, http::status::bad_request, "unauthorized_client", "not this client's grant");
          const auto grant = shared->codes.take(value_of("code"));
          if (!grant || grant->client_id != app.client_id) return token_error(context, http::status::bad_request, "invalid_grant", "the code is not good");
          if (value_of("redirect_uri") != grant->redirect_uri)
            return token_error(context, http::status::bad_request, "invalid_grant", "redirect_uri is not the one the code was given to");
          if (!pkce_ok(value_of("code_verifier"), grant->code_challenge))
            return token_error(context, http::status::bad_request, "invalid_grant", "the code_verifier does not match");
          return shared->parts.issuer->for_person(app, *grant, kStepDeadline, context.executor, [context](Outcome<Issued> issued) {
            if (issued.fault == Fault::refused) return token_error(context, http::status::bad_request, "invalid_grant", issued.message);
            if (!issued.ok()) return token_error(context, http::status::internal_server_error, "server_error", "no tokens could be made");
            token_answer(context, issued.value);
          });
        }
        if (grant_type == "client_credentials") {
          if (!(app.grants & apps::kClientCredentials) || app.auth == apps::ClientAuth::none)
            return token_error(context, http::status::bad_request, "unauthorized_client", "not this client's grant");
          const auto asked = scopes::split(value_of("scope"));
          if (!asked) return token_error(context, http::status::bad_request, "invalid_scope", "scope is a space-separated list of scopes");
          const auto issued = shared->parts.issuer->for_client(app, *asked);
          if (issued.fault == Fault::invalid) return token_error(context, http::status::bad_request, "invalid_scope", issued.message);
          if (!issued.ok()) return token_error(context, http::status::internal_server_error, "server_error", "no token could be made");
          return token_answer(context, issued.value);
        }
        token_error(context, http::status::bad_request, "unsupported_grant_type", "grant_type is authorization_code or client_credentials");
      });
}

void par(const std::shared_ptr<Shared>& shared, RouteContext context) {
  const auto form = http::parse_form(context.body());
  if (!form) return token_error(context, http::status::bad_request, "invalid_request", "the body is a form, one value per name");
  if (form->count("request_uri")) return token_error(context, http::status::bad_request, "invalid_request", "a pushed request has no request_uri");
  shared->parts.clients->authenticate(*context.request, *form, kStepDeadline, context.executor, [shared, context, form = *form](Outcome<apps::App> client) {
    if (!client.ok()) {
      if (client.fault == Fault::refused) return token_error(context, http::status::unauthorized, "invalid_client", client.message);
      return token_error(context, http::status::internal_server_error, "server_error", "the client could not be checked");
    }
    Parameters parameters;
    for (const auto& [name, value] : form) {
      if (name != "client_assertion" && name != "client_assertion_type") parameters.emplace(name, value);
    }
    parameters["client_id"] = client.value.client_id;
    auto checked = check_request(client.value, parameters);
    if (const auto* error = std::get_if<RequestError>(&checked)) return token_error(context, http::status::bad_request, error->error, error->description);
    const auto handle = shared->pushed.put(Pushed{client.value.client_id, parameters});
    http::write_json(context.response, http::status::created,
                     boost::json::object{{"request_uri", std::string(kRequestUriPrefix) + handle}, {"expires_in", shared->pushed.lifetime().count()}});
    context.done();
  });
}

void userinfo(const std::shared_ptr<Shared>& shared, RouteContext context) {
  const auto refuse = [&context](const char* error, const char* description) {
    context.response->set(http::field::www_authenticate, std::string("Bearer realm=\"lugh\", error=\"") + error + "\"");
    http::write_error(context.response, http::status::unauthorized, error, description);
    context.done();
  };
  const auto header = context.request->find(http::field::authorization);
  if (header == context.request->end() || std::string_view(header->value()).rfind("Bearer ", 0) != 0)
    return refuse("invalid_token", "a bearer token is needed");
  const auto bearer = shared->parts.issuer->verify(std::string_view(header->value()).substr(7), std::nullopt);
  if (!bearer || bearer->service || !has(bearer->scopes, "openid")) return refuse("invalid_token", "this token does not open userinfo");
  shared->parts.apps->app(bearer->client_id, kStepDeadline, context.executor, [shared, context, bearer](Outcome<std::optional<apps::App>> app) {
    if (!app.ok())
      return http::write_error(context.response, http::status::internal_server_error, "failed", "the request could not be completed"), context.done();
    shared->parts.issuer->person_claims(
        bearer->subject, bearer->scopes, app.value, kStepDeadline, context.executor, [context](Outcome<boost::json::object> claims) {
          if (claims.fault == Fault::refused) {
            http::write_error(context.response, http::status::unauthorized, "invalid_token", "this token's user cannot have claims");
            return context.done();
          }
          if (!claims.ok()) {
            http::write_error(context.response, http::status::internal_server_error, "failed", "the request could not be completed");
            return context.done();
          }
          http::write_json(context.response, http::status::ok, claims.value);
          context.done();
        });
  });
}

std::string consent_page(const apps::App& app, const AuthorizationRequest& request, const std::string& id, const std::string& csrf) {
  std::string list;
  for (const auto& scope : request.scopes) list += "<li>" + signin::escape(meaning(scope)) + "</li>\n";
  const auto hidden = "<input type=\"hidden\" name=\"csrf\" value=\"" + signin::escape(csrf) + "\">\n<input type=\"hidden\" name=\"id\" value=\"" +
                      signin::escape(id) + "\">\n";
  return signin::page("Allow " + app.name + "?",
                      "<p><strong>" + signin::escape(app.name) + "</strong> asks to:</p>\n<ul>\n" + list + "</ul>\n" +
                          "<form method=\"post\" action=\"/oauth2/consent\">\n" + hidden +
                          "<input type=\"hidden\" name=\"decision\" value=\"allow\">\n<button type=\"submit\">Allow</button>\n</form>\n"
                          "<form class=\"alternative\" method=\"post\" action=\"/oauth2/consent\">\n" +
                          hidden + "<input type=\"hidden\" name=\"decision\" value=\"deny\">\n<button type=\"submit\">Deny</button>\n</form>\n");
}

}  // namespace

FlowRoutes::FlowRoutes(Parts parts) : _shared(std::make_shared<Shared>(std::move(parts))) {}

void FlowRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto shared = _shared;
  router.add_open(verb::get, "/oauth2/authorize", [shared](RouteContext context) { authorize(shared, std::move(context)); });
  router.add_open(verb::get, "/oauth2/authorize/resume", [shared](RouteContext context) {
    const auto id = context.query.count("id") ? context.query.at("id") : std::string();
    auto pending = shared->pending.take(id);
    if (!pending) return error_page(context, "That sign-in took too long, or was already used. Go back to the application and start again.");
    decide(shared, context, std::move(*pending));
  });
  router.add_open(verb::get, "/oauth2/consent", [shared](RouteContext context) {
    const auto id = context.query.count("id") ? context.query.at("id") : std::string();
    const auto session = session_of(*shared, context);
    const auto pending = shared->pending.peek(id);
    if (!session || !pending) return error_page(context, "That request took too long, or was already answered. Go back to the application and start again.");
    shared->parts.apps->app(
        pending->request.client_id, kStepDeadline, context.executor, [context, pending, id, session](Outcome<std::optional<apps::App>> app) {
          if (!app.ok() || !app.value) return error_page(context, "The application could not be read.");
          signin::write_page(context.response, http::status::ok, consent_page(*app.value, pending->request, id, session::Sessions::csrf_token(*session)));
          context.done();
        });
  });
  router.add_open(verb::post, "/oauth2/consent", [shared](RouteContext context) {
    const auto form = http::parse_form(context.body());
    const auto session = session_of(*shared, context);
    if (!form || !session || !session::Sessions::csrf_ok(*session, form->count("csrf") ? form->at("csrf") : ""))
      return error_page(context, "That answer did not come from Lugh's own page.");
    auto pending = shared->pending.take(form->count("id") ? form->at("id") : "");
    if (!pending) return error_page(context, "That request took too long, or was already answered. Go back to the application and start again.");
    if (!form->count("decision") || form->at("decision") != "allow")
      return error_back(*shared, context, pending->request, "access_denied", "the user did not allow it");
    shared->parts.consents->grant(audit::Actor{session->user_id, context.remote}, session->user_id, pending->request.client_id, pending->request.scopes,
                                  kStepDeadline, context.executor, [shared, context, pending, session](Outcome<> granted) {
                                    if (!granted.ok()) return error_back(*shared, context, pending->request, "server_error", "consent could not be kept");
                                    issue_code(shared, context, pending->request, *session);
                                  });
  });
  router.add_open(verb::post, "/oauth2/par", [shared](RouteContext context) { par(shared, std::move(context)); });
  router.add_open(verb::post, "/oauth2/token", [shared](RouteContext context) { token(shared, std::move(context)); });
  router.add_open(verb::get, "/oauth2/userinfo", [shared](RouteContext context) { userinfo(shared, std::move(context)); });
  router.add_open(verb::post, "/oauth2/userinfo", [shared](RouteContext context) { userinfo(shared, std::move(context)); });
}

}  // namespace lugh::oauth

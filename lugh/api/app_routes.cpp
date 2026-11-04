//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/app_routes.h"

#include <array>
#include <utility>

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"

namespace lugh::api {

namespace {

using apps::App;
using Answer = Outcome<>;

Answer bad(std::string why) { return Answer::failure(Fault::invalid, std::move(why)); }

constexpr std::array<std::pair<apps::Kind, const char*>, 5> kKinds{
    {{apps::Kind::web, "web"}, {apps::Kind::spa, "spa"}, {apps::Kind::native, "native"}, {apps::Kind::service, "service"}, {apps::Kind::api, "api"}}};
constexpr std::array<std::pair<apps::ClientAuth, const char*>, 4> kAuths{{{apps::ClientAuth::none, "none"},
                                                                          {apps::ClientAuth::private_key_jwt, "private_key_jwt"},
                                                                          {apps::ClientAuth::tls_client_auth, "tls_client_auth"},
                                                                          {apps::ClientAuth::client_secret_basic, "client_secret_basic"}}};
constexpr std::array<std::pair<std::uint8_t, const char*>, 4> kGrants{{{apps::kAuthorizationCode, "authorization_code"},
                                                                       {apps::kRefreshToken, "refresh_token"},
                                                                       {apps::kDeviceCode, "urn:ietf:params:oauth:grant-type:device_code"},
                                                                       {apps::kClientCredentials, "client_credentials"}}};
constexpr std::array<std::pair<apps::SenderConstraint, const char*>, 3> kSenders{
    {{apps::SenderConstraint::none, "none"}, {apps::SenderConstraint::dpop, "dpop"}, {apps::SenderConstraint::mtls, "mtls"}}};

template <typename E, std::size_t N>
const char* name_of(const std::array<std::pair<E, const char*>, N>& names, E value) {
  for (const auto& [one, name] : names) {
    if (one == value) return name;
  }
  return "";
}

template <typename E, std::size_t N>
std::optional<E> value_of(const std::array<std::pair<E, const char*>, N>& names, std::string_view text) {
  for (const auto& [one, name] : names) {
    if (text == name) return one;
  }
  return std::nullopt;
}

boost::json::array strings(const std::vector<std::string>& values) {
  boost::json::array out;
  for (const auto& value : values) out.push_back(boost::json::string(value));
  return out;
}

Answer string_of(const boost::json::value& value, const char* name, std::string& out) {
  if (!value.is_string()) return bad(std::string(name) + " must be a string");
  out = std::string(value.as_string());
  return Answer::success();
}

Answer strings_of(const boost::json::value& value, const char* name, std::vector<std::string>& out) {
  if (!value.is_array()) return bad(std::string(name) + " must be an array of strings");
  out.clear();
  for (const auto& one : value.as_array()) {
    if (!one.is_string()) return bad(std::string(name) + " must be an array of strings");
    out.emplace_back(one.as_string());
  }
  return Answer::success();
}

Answer bool_of(const boost::json::value& value, const char* name, bool& out) {
  if (!value.is_bool()) return bad(std::string(name) + " must be true or false");
  out = value.as_bool();
  return Answer::success();
}

Answer seconds_of(const boost::json::value& value, const char* name, std::uint32_t& out) {
  if (!value.is_int64() && !value.is_uint64()) return bad(std::string(name) + " must be a whole number of seconds");
  const auto number = value.is_int64() ? value.as_int64() : static_cast<std::int64_t>(std::min<std::uint64_t>(value.as_uint64(), INT64_MAX));
  if (number < 0 || number > UINT32_MAX) return bad(std::string(name) + " is out of range");
  out = static_cast<std::uint32_t>(number);
  return Answer::success();
}

template <typename E, std::size_t N>
Answer choice_of(const boost::json::value& value, const char* name, const std::array<std::pair<E, const char*>, N>& names, E& out) {
  std::string text;
  if (const auto ok = string_of(value, name, text); !ok.ok()) return ok;
  const auto found = value_of(names, text);
  if (!found) {
    std::string wanted;
    for (const auto& [one, spelled] : names) wanted += (wanted.empty() ? "" : ", ") + std::string(spelled);
    return bad(std::string(name) + " is one of " + wanted);
  }
  out = *found;
  return Answer::success();
}

void write_app(const http::RouteContext& context, http::status status, const App& app, std::optional<std::string> secret = std::nullopt) {
  auto body = app_json(app);
  // Shown this once; only its hash is kept.
  if (secret) body["client_secret"] = *secret;
  http::write_json(context.response, status, body);
  context.response->set(http::field::etag, etag(app.version));
}

void answer_no_such(const http::RouteContext& context) {
  http::write_error(context.response, http::status::not_found, "not_found", "no such application");
  context.done();
}

}  // namespace

boost::json::object app_json(const App& app) {
  boost::json::object out;
  out["client_id"] = app.client_id;
  out["name"] = app.name;
  out["icon_uri"] = app.icon_uri;
  out["home_uri"] = app.home_uri;
  out["kind"] = name_of(kKinds, app.kind);
  if (!app.prefix.empty()) out["scope_prefix"] = app.prefix;
  out["client_authentication"] = name_of(kAuths, app.auth);
  if (!app.jwks.empty()) {
    boost::system::error_code ec;
    out["jwks"] = boost::json::parse(app.jwks, ec);
  }
  if (!app.tls_subject.empty()) out["tls_client_auth_subject_dn"] = app.tls_subject;
  if (!app.tls_thumbprint.empty()) out["tls_client_auth_thumbprint"] = app.tls_thumbprint;
  if (app.auth == apps::ClientAuth::client_secret_basic) {
    // When the rotated secret stops working, if there is one: never the secret.
    for (const auto& secret : app.secrets) {
      if (secret.expires != 0) out["previous_secret_expires_at"] = timestamp(secret.expires);
    }
  }
  out["redirect_uris"] = strings(app.redirect_uris);
  out["post_logout_redirect_uris"] = strings(app.post_logout_uris);
  out["backchannel_logout_uri"] = app.backchannel_logout_uri;
  boost::json::array grants;
  for (const auto& [bit, name] : kGrants) {
    if (app.grants & bit) grants.push_back(boost::json::string(name));
  }
  out["grant_types"] = std::move(grants);
  out["scopes"] = strings(app.scopes);
  out["audiences"] = strings(app.audiences);
  out["client_scopes"] = strings(app.client_scopes);
  out["access"] = strings(app.access);
  boost::json::object roles;
  for (const auto& mapping : app.roles) roles[mapping.group_id] = strings(mapping.roles);
  out["roles"] = std::move(roles);
  out["acr"] = app.acr.empty() ? boost::json::value(nullptr) : boost::json::value(app.acr);
  out["max_age"] = app.max_age;
  out["first_party"] = app.first_party;
  out["opaque_access_tokens"] = app.opaque_access_tokens;
  out["sender_constraint"] = name_of(kSenders, app.sender);
  out["lifetimes"] = {{"access_token", app.access_seconds},
                      {"id_token", app.id_seconds},
                      {"refresh_idle", app.refresh_idle_seconds},
                      {"refresh_absolute", app.refresh_absolute_seconds}};
  out["enabled"] = app.state == apps::State::enabled;
  out["created_at"] = timestamp(app.created);
  out["updated_at"] = timestamp(app.updated);
  return out;
}

Outcome<> app_from_json(const boost::json::object& body, bool creating, App& app) {
  for (const auto& member : body) {
    const std::string key(member.key());
    const auto& value = member.value();
    Answer ok = Answer::success();
    if (key == "name") {
      ok = string_of(value, "name", app.name);
    } else if (key == "icon_uri") {
      ok = string_of(value, "icon_uri", app.icon_uri);
    } else if (key == "home_uri") {
      ok = string_of(value, "home_uri", app.home_uri);
    } else if (key == "kind" || key == "scope_prefix") {
      if (!creating) return bad(key + " never changes");
      ok = key == "kind" ? choice_of(value, "kind", kKinds, app.kind) : string_of(value, "scope_prefix", app.prefix);
    } else if (key == "client_authentication") {
      ok = choice_of(value, "client_authentication", kAuths, app.auth);
    } else if (key == "jwks") {
      if (value.is_null()) {
        app.jwks.clear();
      } else if (!value.is_object()) {
        return bad("jwks must be a JWK Set object");
      } else {
        app.jwks = boost::json::serialize(value);
      }
    } else if (key == "tls_client_auth_subject_dn") {
      ok = string_of(value, "tls_client_auth_subject_dn", app.tls_subject);
    } else if (key == "tls_client_auth_thumbprint") {
      ok = string_of(value, "tls_client_auth_thumbprint", app.tls_thumbprint);
    } else if (key == "redirect_uris") {
      ok = strings_of(value, "redirect_uris", app.redirect_uris);
    } else if (key == "post_logout_redirect_uris") {
      ok = strings_of(value, "post_logout_redirect_uris", app.post_logout_uris);
    } else if (key == "backchannel_logout_uri") {
      ok = string_of(value, "backchannel_logout_uri", app.backchannel_logout_uri);
    } else if (key == "grant_types") {
      std::vector<std::string> names;
      ok = strings_of(value, "grant_types", names);
      if (!ok.ok()) return ok;
      app.grants = 0;
      for (const auto& name : names) {
        bool known = false;
        for (const auto& [bit, spelled] : kGrants) {
          if (name == spelled) {
            app.grants |= bit;
            known = true;
          }
        }
        if (!known) return bad("grant_types: " + name + " is not a grant Lugh offers");
      }
    } else if (key == "scopes") {
      ok = strings_of(value, "scopes", app.scopes);
    } else if (key == "audiences") {
      ok = strings_of(value, "audiences", app.audiences);
    } else if (key == "client_scopes") {
      ok = strings_of(value, "client_scopes", app.client_scopes);
    } else if (key == "acr") {
      if (value.is_null()) {
        app.acr.clear();
      } else {
        ok = string_of(value, "acr", app.acr);
      }
    } else if (key == "max_age") {
      ok = seconds_of(value, "max_age", app.max_age);
    } else if (key == "first_party") {
      ok = bool_of(value, "first_party", app.first_party);
    } else if (key == "opaque_access_tokens") {
      ok = bool_of(value, "opaque_access_tokens", app.opaque_access_tokens);
    } else if (key == "sender_constraint") {
      ok = choice_of(value, "sender_constraint", kSenders, app.sender);
    } else if (key == "lifetimes") {
      if (!value.is_object()) return bad("lifetimes must be an object");
      for (const auto& one : value.as_object()) {
        const std::string name(one.key());
        if (name == "access_token") {
          ok = seconds_of(one.value(), "lifetimes.access_token", app.access_seconds);
        } else if (name == "id_token") {
          ok = seconds_of(one.value(), "lifetimes.id_token", app.id_seconds);
        } else if (name == "refresh_idle") {
          ok = seconds_of(one.value(), "lifetimes.refresh_idle", app.refresh_idle_seconds);
        } else if (name == "refresh_absolute") {
          ok = seconds_of(one.value(), "lifetimes.refresh_absolute", app.refresh_absolute_seconds);
        } else {
          return bad("unknown field lifetimes." + name);
        }
        if (!ok.ok()) return ok;
      }
    } else if (key == "enabled") {
      bool enabled = true;
      ok = bool_of(value, "enabled", enabled);
      app.state = enabled ? apps::State::enabled : apps::State::disabled;
    } else {
      return bad("unknown field " + key);
    }
    if (!ok.ok()) return ok;
  }
  return Answer::success();
}

AppRoutes::AppRoutes(std::shared_ptr<apps::Apps> apps) : _apps(std::move(apps)) {}

void AppRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto bind = [this](auto method) { return [this, method](http::RouteContext context) { (this->*method)(std::move(context)); }; };
  router.add(verb::get, "/api/v1/apps", kDirectoryRead, bind(&AppRoutes::_list));
  router.add(verb::post, "/api/v1/apps", kAppsWrite, bind(&AppRoutes::_create));
  router.add(verb::get, "/api/v1/apps/{id}", kDirectoryRead, bind(&AppRoutes::_get));
  router.add(verb::patch, "/api/v1/apps/{id}", kAppsWrite, bind(&AppRoutes::_update));
  router.add(verb::delete_, "/api/v1/apps/{id}", kAppsWrite, bind(&AppRoutes::_remove));
  router.add(verb::put, "/api/v1/apps/{id}/access/{group}", kAppsWrite, [this](http::RouteContext context) { _access(std::move(context), true); });
  router.add(verb::delete_, "/api/v1/apps/{id}/access/{group}", kAppsWrite, [this](http::RouteContext context) { _access(std::move(context), false); });
  router.add(verb::put, "/api/v1/apps/{id}/roles/{group}", kAppsWrite, bind(&AppRoutes::_roles));
  router.add(verb::post, "/api/v1/apps/{id}/secret", kAppsWrite, bind(&AppRoutes::_secret));
}

void AppRoutes::_list(http::RouteContext context) const {
  _apps->apps(kRouteDeadline, context.executor, [context](Outcome<std::vector<App>> all) {
    if (!all.ok()) return answer_fault(context, all);
    boost::json::array list;
    for (const auto& app : all.value) list.push_back(app_json(app));
    answer_json(context, http::status::ok, boost::json::object{{"apps", std::move(list)}});
  });
}

void AppRoutes::_create(http::RouteContext context) {
  const auto body = http::parse_object(context.body());
  if (!body) {
    http::write_error(context.response, http::status::bad_request, "invalid", "the body must be a JSON object");
    return context.done();
  }
  App draft;
  if (const auto ok = app_from_json(*body, true, draft); !ok.ok()) return answer_fault(context, ok);
  _apps->create(actor_of(context), std::move(draft), kRouteDeadline, context.executor, [context](Outcome<apps::Apps::Made> made) {
    if (!made.ok()) return answer_fault(context, made);
    std::optional<std::string> secret;
    if (made.value.secret) secret = std::string(secret_text(*made.value.secret));
    write_app(context, http::status::created, made.value.app, secret);
    context.response->set(http::field::location, "/api/v1/apps/" + made.value.app.client_id);
    context.done();
  });
}

void AppRoutes::_get(http::RouteContext context) const {
  _apps->app(context.parameter("id"), kRouteDeadline, context.executor, [context](Outcome<std::optional<App>> found) {
    if (!found.ok()) return answer_fault(context, found);
    if (!found.value) return answer_no_such(context);
    write_app(context, http::status::ok, *found.value);
    context.done();
  });
}

void AppRoutes::_update(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  const auto body = http::parse_object(context.body());
  if (!body) {
    http::write_error(context.response, http::status::bad_request, "invalid", "the body must be a JSON object");
    return context.done();
  }
  const auto apps = _apps;
  apps->app(context.parameter("id"), kRouteDeadline, context.executor, [=](Outcome<std::optional<App>> found) {
    if (!found.ok()) return answer_fault(context, found);
    if (!found.value) return answer_no_such(context);
    auto changed = *found.value;
    if (const auto ok = app_from_json(*body, false, changed); !ok.ok()) return answer_fault(context, ok);
    // With If-Match: *, the change is made against what was just read, never blind.
    const auto expected = precondition.expected.value_or(found.value->version);
    apps->replace(actor_of(context), std::move(changed), expected, kRouteDeadline, context.executor, [context](Outcome<App> made) {
      if (!made.ok()) return answer_fault(context, made);
      write_app(context, http::status::ok, made.value);
      context.done();
    });
  });
}

void AppRoutes::_remove(http::RouteContext context) {
  const auto precondition = if_match(context);
  if (!precondition.ok) return context.done();
  _apps->remove(actor_of(context), context.parameter("id"), precondition.expected, kRouteDeadline, context.executor, [context](Outcome<> removed) {
    if (!removed.ok()) return answer_fault(context, removed);
    http::write_no_content(context.response);
    context.done();
  });
}

void AppRoutes::_access(http::RouteContext context, bool allowed) {
  _apps->access_set(actor_of(context), context.parameter("id"), context.parameter("group"), allowed, kRouteDeadline, context.executor,
                    [context](Outcome<App> made) {
                      if (!made.ok()) return answer_fault(context, made);
                      write_app(context, http::status::ok, made.value);
                      context.done();
                    });
}

void AppRoutes::_roles(http::RouteContext context) {
  const auto body = body_object(context, {"roles"});
  if (!body) return context.done();
  std::vector<std::string> roles;
  const auto it = body->find("roles");
  if (it == body->end()) {
    http::write_error(context.response, http::status::bad_request, "invalid", "roles is an array of role names, empty to clear");
    return context.done();
  }
  if (const auto ok = strings_of(it->value(), "roles", roles); !ok.ok()) return answer_fault(context, ok);
  _apps->roles_set(actor_of(context), context.parameter("id"), context.parameter("group"), std::move(roles), kRouteDeadline, context.executor,
                   [context](Outcome<App> made) {
                     if (!made.ok()) return answer_fault(context, made);
                     write_app(context, http::status::ok, made.value);
                     context.done();
                   });
}

void AppRoutes::_secret(http::RouteContext context) {
  if (!body_object(context, {})) return context.done();
  _apps->secret_rotate(actor_of(context), context.parameter("id"), kRouteDeadline, context.executor, [context](Outcome<apps::Apps::Made> made) {
    if (!made.ok()) return answer_fault(context, made);
    write_app(context, http::status::created, made.value.app, std::string(secret_text(*made.value.secret)));
    context.done();
  });
}

}  // namespace lugh::api

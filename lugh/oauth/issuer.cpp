//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/issuer.h"

#include <algorithm>
#include <variant>

#include "dannan/identity/crypto.h"
#include "lugh/client/access_token.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"
#include "lugh/oauth/request.h"
#include "lugh/scopes/scope.h"

namespace lugh::oauth {

namespace {

constexpr std::uint64_t kLogoutTokenSeconds = 120;
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

boost::json::array strings(const std::vector<std::string>& values) {
  boost::json::array out;
  for (const auto& value : values) out.push_back(boost::json::string(value));
  return out;
}

bool has(const std::vector<std::string>& list, std::string_view item) { return std::find(list.begin(), list.end(), item) != list.end(); }

std::string random_id() { return encoding::base64url(dannan::identity::random_bytes(16)); }

// OIDC Core 3.1.3.6: the left half of the SHA-256 of the access token, base64url.
std::string at_hash(const std::string& access_token) {
  const auto hash = dannan::identity::sha256(byte_span(access_token));
  return encoding::base64url(std::span<const unsigned char>(hash.bytes).first(16));
}

}  // namespace

std::vector<std::string> audiences_of(const apps::App& app) { return app.audiences.empty() ? std::vector<std::string>{app.client_id} : app.audiences; }

TokenIssuer::TokenIssuer(std::shared_ptr<const tokens::SigningKeys> keys, std::string issuer, const dannan::contract::WallClock& wall,
                         const dannan::contract::TimeSource& time, std::shared_ptr<directory::Directory> directory, std::shared_ptr<scopes::Grants> grants)
    : _keys(std::move(keys)),
      _issuer(std::move(issuer)),
      _wall(wall),
      _directory(std::move(directory)),
      _grants(std::move(grants)),
      // An access token lives an hour at most, and a minute's skew after.
      _revoked(std::make_shared<Expiring<bool>>(time, std::chrono::seconds(3600 + 120), 100000)),
      _opaque(std::make_shared<Expiring<std::string>>(time, std::chrono::seconds(3600 + 120), 100000)) {}

std::string TokenIssuer::_as_issued(const apps::App& app, std::string signed_token) const {
  if (!app.opaque_access_tokens) return signed_token;
  return kOpaquePrefix + _opaque->put(std::move(signed_token));
}

void TokenIssuer::revoke_access(const Bearer& bearer) {
  if (const auto jti = bearer.claims.if_contains("jti"); jti && jti->is_string()) _revoked->put_as(std::string(jti->as_string()), true);
}

void TokenIssuer::person_claims(std::string user_id, std::vector<std::string> scopes, std::optional<apps::App> app, Deadline deadline, Executor executor,
                                Done<Outcome<boost::json::object>> done) {
  using Answer = Outcome<boost::json::object>;
  auto answer = answering<boost::json::object>(deadline, executor, std::move(done), "the claims were not read within the deadline");
  auto self = shared_from_this();
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer->finish(Answer::from(user));
    if (!user.value || user.value->disabled || !user.value->enrolled) return answer->finish(Answer::failure(Fault::refused, "the user cannot have tokens"));
    boost::json::object claims;
    claims["sub"] = user_id;
    if (has(scopes, "profile")) {
      claims["name"] = user.value->display_name.empty() ? user.value->name : user.value->display_name;
      if (!user.value->given_name.empty()) claims["given_name"] = user.value->given_name;
      if (!user.value->family_name.empty()) claims["family_name"] = user.value->family_name;
      claims["preferred_username"] = user.value->name;
      claims["updated_at"] = user.value->updated;
    }
    if (has(scopes, "email") && !user.value->email.empty()) {
      claims["email"] = user.value->email;
      // Lugh records an address an administrator gave; it has not proved the person reads it.
      claims["email_verified"] = false;
    }
    const bool want_groups = has(scopes, "groups");
    const bool want_roles = app && !app->roles.empty();
    if (!want_groups && !want_roles) return answer->finish(Answer::success(std::move(claims)));
    self->_directory->groups_of(user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> ids) mutable {
      if (!ids.ok()) return answer->finish(Answer::from(ids));
      std::vector<std::string> roles;
      if (want_roles) {
        for (const auto& mapping : app->roles) {
          if (has(ids.value, mapping.group_id)) roles.insert(roles.end(), mapping.roles.begin(), mapping.roles.end());
        }
        if (!roles.empty()) claims["roles"] = strings(scopes::united(std::move(roles)));
      }
      if (!want_groups) return answer->finish(Answer::success(std::move(claims)));
      self->_directory->groups(kStepDeadline, executor, [=](Outcome<std::vector<directory::Group>> groups) mutable {
        if (!groups.ok()) return answer->finish(Answer::from(groups));
        std::vector<std::string> names;
        for (const auto& group : groups.value) {
          if (has(ids.value, group.id)) names.push_back(group.name);
        }
        claims["groups"] = strings(scopes::united(std::move(names)));
        answer->finish(Answer::success(std::move(claims)));
      });
    });
  });
}

void TokenIssuer::for_person(apps::App app, CodeGrant grant, Deadline deadline, Executor executor, Done<Outcome<Issued>> done, bool id_token,
                             std::optional<boost::json::object> cnf) {
  using Answer = Outcome<Issued>;
  auto answer = answering<Issued>(deadline, executor, std::move(done), "no tokens were made within the deadline");
  const auto signer = _keys->signer();
  if (!signer) return answer->finish(Answer::failure(Fault::failed, "no key signs yet"));
  auto self = shared_from_this();
  _grants->effective(grant.user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> held) {
    if (!held.ok()) return answer->finish(Answer::from(held));
    const auto audiences = audiences_of(app);
    const auto scopes = granted_scopes(grant.scopes, held.value, audiences);
    self->person_claims(grant.user_id, scopes, app, kStepDeadline, executor, [=](Outcome<boost::json::object> person) {
      if (!person.ok()) return answer->finish(Answer::from(person));
      const auto now = self->_now();
      boost::json::object access;
      access["iss"] = self->_issuer;
      access["sub"] = grant.user_id;
      access["aud"] = strings(audiences);
      access["client_id"] = app.client_id;
      access["iat"] = now;
      access["nbf"] = now;
      access["exp"] = now + app.access_seconds;
      access["jti"] = random_id();
      access["scope"] = scopes::join(scopes);
      access["acr"] = std::string(authn::acr(grant.acr));
      access["amr"] = strings(grant.amr);
      access["auth_time"] = grant.auth_time;
      access["sid"] = grant.sid;
      if (cnf) access["cnf"] = *cnf;

      Issued issued;
      issued.access_token = self->_as_issued(app, client::jws_sign(*signer->key, signer->kid, "at+jwt", access));
      if (cnf && cnf->contains("jkt")) issued.token_type = "DPoP";
      issued.expires_in = app.access_seconds;
      issued.scopes = scopes;
      if (id_token && has(scopes, "openid")) {
        auto id = person.value;
        id["iss"] = self->_issuer;
        id["aud"] = app.client_id;
        id["azp"] = app.client_id;
        id["iat"] = now;
        id["exp"] = now + app.id_seconds;
        id["auth_time"] = grant.auth_time;
        id["nonce"] = grant.nonce;
        id["acr"] = std::string(authn::acr(grant.acr));
        id["amr"] = strings(grant.amr);
        id["sid"] = grant.sid;
        id["at_hash"] = at_hash(issued.access_token);
        issued.id_token = client::jws_sign(*signer->key, signer->kid, "JWT", id);
      }
      answer->finish(Answer::success(std::move(issued)));
    });
  });
}

Outcome<Issued> TokenIssuer::for_client(const apps::App& app, const std::vector<std::string>& asked, std::optional<boost::json::object> cnf) const {
  using Answer = Outcome<Issued>;
  const auto signer = _keys->signer();
  if (!signer) return Answer::failure(Fault::failed, "no key signs yet");
  for (const auto& scope : asked) {
    if (!has(app.client_scopes, scope)) return Answer::failure(Fault::invalid, "this client does not hold " + scope);
  }
  const auto audiences = audiences_of(app);
  const auto scopes = granted_scopes(asked.empty() ? app.client_scopes : asked, app.client_scopes, audiences);
  const auto now = _now();
  boost::json::object access;
  access["iss"] = _issuer;
  access["sub"] = app.client_id;
  access["aud"] = strings(audiences);
  access["client_id"] = app.client_id;
  access["iat"] = now;
  access["nbf"] = now;
  access["exp"] = now + app.access_seconds;
  access["jti"] = random_id();
  access["scope"] = scopes::join(scopes);
  if (cnf) access["cnf"] = *cnf;
  Issued issued;
  issued.access_token = _as_issued(app, client::jws_sign(*signer->key, signer->kid, "at+jwt", access));
  if (cnf && cnf->contains("jkt")) issued.token_type = "DPoP";
  issued.expires_in = app.access_seconds;
  issued.scopes = scopes;
  return Answer::success(std::move(issued));
}

std::optional<IdTokenHint> TokenIssuer::id_token_hint(std::string_view token) const {
  const auto jws = client::jws_parse(token);
  if (!jws || jws->typ != "JWT" || !client::jws_verify(*jws, _keys->published())) return std::nullopt;
  const auto text = [&](const char* name) {
    const auto found = jws->claims.if_contains(name);
    return found && found->is_string() ? std::string(found->as_string()) : std::string();
  };
  IdTokenHint hint{text("aud"), text("sub"), text("sid")};
  if (text("iss") != _issuer || hint.client_id.empty() || hint.subject.empty()) return std::nullopt;
  return hint;
}

std::optional<std::string> TokenIssuer::logout_token(const std::string& client_id, const std::string& user_id, const std::string& sid) const {
  const auto signer = _keys->signer();
  if (!signer) return std::nullopt;
  const auto now = _now();
  boost::json::object claims;
  claims["iss"] = _issuer;
  claims["sub"] = user_id;
  claims["aud"] = client_id;
  claims["iat"] = now;
  claims["exp"] = now + kLogoutTokenSeconds;
  claims["jti"] = random_id();
  claims["sid"] = sid;
  claims["events"] = boost::json::object{{"http://schemas.openid.net/event/backchannel-logout", boost::json::object{}}};
  return client::jws_sign(*signer->key, signer->kid, "logout+jwt", claims);
}

std::optional<Bearer> TokenIssuer::verify(std::string_view token, std::optional<std::string_view> audience) const {
  std::optional<std::string> behind;
  if (token.starts_with(kOpaquePrefix)) {
    behind = _opaque->peek(token.substr(std::string_view(kOpaquePrefix).size()));
    if (!behind) return std::nullopt;
  }
  // The checks a relying party makes too are the client library's; what only this node can see,
  // an opaque handle and a revoked jti, is added here.
  auto checked = client::check_access_token(behind ? std::string_view(*behind) : token, _keys->published(), _issuer, _now(), audience);
  auto* access = std::get_if<client::AccessToken>(&checked);
  if (!access || _revoked->peek(access->jti)) return std::nullopt;
  Bearer bearer;
  bearer.claims = std::move(access->claims);
  bearer.subject = std::move(access->subject);
  bearer.client_id = std::move(access->client_id);
  bearer.service = bearer.subject == bearer.client_id;
  bearer.opaque = behind.has_value();
  bearer.jkt = std::move(access->jkt);
  bearer.x5t = std::move(access->x5t);
  if (const auto scope = bearer.claims.if_contains("scope"); scope && scope->is_string()) {
    if (auto split = scopes::split(scope->as_string())) bearer.scopes = std::move(*split);
  }
  return bearer;
}

}  // namespace lugh::oauth

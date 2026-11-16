//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/factor_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/representations.h"
#include "lugh/api/session_routes.h"
#include "lugh/core/encoding.h"

namespace lugh::api {

using authn::Step;
using http::RouteContext;

struct FactorRoutes::Shared {
  std::shared_ptr<session::Sessions> sessions;
  std::shared_ptr<session::Reauthentications> windows;
  std::shared_ptr<directory::Directory> directory;
  std::shared_ptr<authn::Factors> factors;
  std::shared_ptr<authn::Authenticator> authenticator;
  std::string totp_issuer;
  std::optional<FactorRoutes::WebAuthn> webauthn;
};

FactorRoutes::FactorRoutes(std::shared_ptr<session::Sessions> sessions, std::shared_ptr<session::Reauthentications> windows,
                           std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Factors> factors,
                           std::shared_ptr<authn::Authenticator> authenticator, std::string totp_issuer)
    : _shared(std::make_shared<Shared>(Shared{std::move(sessions), std::move(windows), std::move(directory), std::move(factors), std::move(authenticator),
                                              std::move(totp_issuer), std::nullopt})) {}

void FactorRoutes::webauthn(WebAuthn settings) { _shared->webauthn = std::move(settings); }

namespace {

using Shared = FactorRoutes::Shared;

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

// A challenge is bound to the session it was issued to, and kept apart from a sign-in's.
std::string binding_of(const session::Session& session) { return "me:" + session.sid; }

boost::json::array credential_list(const std::vector<std::string>& ids) {
  boost::json::array out;
  for (const auto& id : ids) out.push_back(boost::json::object{{"type", "public-key"}, {"id", encoding::base64url(bytes_of(id))}});
  return out;
}

void answer_error(const RouteContext& context, http::status status, std::string code, std::string message) {
  http::write_error(context.response, status, std::move(code), std::move(message));
  context.done();
}

// The person's own session, or the 403 sent.
std::optional<session::Session> own(const Shared& shared, const RouteContext& context) {
  auto session = own_session(*shared.sessions, context);
  if (!session) answer_error(context, http::status::forbidden, "forbidden", "factors are changed through your own signed-in session");
  return session;
}

// The session's window open, or the 403 sent.
bool window_open(const Shared& shared, const RouteContext& context, const session::Session& session) {
  if (shared.windows->open_now(session.sid)) return true;
  answer_error(context, http::status::forbidden, "reauthentication_required", "prove one of your factors first: POST /api/v1/me/reauthenticate");
  return false;
}

// Where WebAuthn is offered, or the 404 sent.
bool offered(const Shared& shared, const RouteContext& context) {
  if (shared.webauthn) return true;
  answer_error(context, http::status::not_found, "not_found", "WebAuthn is not offered here");
  return false;
}

// A base64url member, decoded; nothing when it is missing or is not base64url.
std::optional<Bytes> bytes_member(const boost::json::object& object, std::string_view name) {
  const auto* found = object.if_contains(name);
  if (found == nullptr || !found->is_string()) return std::nullopt;
  return encoding::base64url_decode(std::string(found->as_string()));
}

std::string text_of(const Bytes& bytes) { return std::string(bytes.begin(), bytes.end()); }

webauthn::Expected expected_of(const FactorRoutes::WebAuthn& settings, std::string challenge) {
  webauthn::Expected expected;
  expected.rp_id = settings.rp_id;
  expected.origins = settings.origins;
  expected.challenge = std::move(challenge);
  return expected;
}

void answer_factors(const RouteContext& context, const std::vector<authn::FactorInfo>& found) {
  boost::json::array list;
  for (const auto& factor : found) list.push_back(factor_json(factor));
  answer_json(context, http::status::ok, boost::json::object{{"factors", std::move(list)}});
}

// The options for a ceremony (W3C WebAuthn 5.4 and 5.5): to prove a credential the person has, or
// to register a new one, which needs the window open, as every change does.
void options(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  if (!offered(*shared, context)) return;
  const auto session = own(*shared, context);
  if (!session) return;
  const auto body = body_object(context, {"purpose"});
  std::optional<std::string> purpose;
  if (!body || !string_member(context, *body, "purpose", purpose)) return context.done();
  if (!purpose || (*purpose != "reauthenticate" && *purpose != "register"))
    return answer_error(context, http::status::bad_request, "invalid", "purpose is reauthenticate or register");
  if (*purpose == "register" && !window_open(*shared, context, *session)) return;

  const auto& settings = *shared->webauthn;
  boost::json::object out;
  out["challenge"] = encoding::base64url(bytes_of(settings.challenges->issue(binding_of(*session))));
  out["timeout"] = 300000;
  const auto user_id = session->user_id;
  if (*purpose == "reauthenticate") {
    out["rpId"] = settings.rp_id;
    out["userVerification"] = "preferred";
    return shared->factors->webauthn_credentials(user_id, kRouteDeadline, context.executor, [context, out](Outcome<std::vector<std::string>> ids) mutable {
      if (!ids.ok()) return answer_fault(context, ids);
      out["allowCredentials"] = credential_list(ids.value);
      answer_json(context, http::status::ok, out);
    });
  }
  shared->directory->user(user_id, kRouteDeadline, context.executor, [shared, context, out, user_id](Outcome<std::optional<directory::User>> found) mutable {
    if (!found.ok()) return answer_fault(context, found);
    if (!found.value) return answer_fault(context, Outcome<>::failure(Fault::not_found, "no such user"));
    const auto& relying_party = *shared->webauthn;
    out["rp"] = boost::json::object{{"id", relying_party.rp_id}, {"name", relying_party.rp_name}};
    // The user handle is the immutable id, never a name or an address (WebAuthn 14.6.1), as at
    // enrolment, so a passkey made here signs in alone as one made there does.
    out["user"] = boost::json::object{{"id", encoding::base64url(bytes_of(user_id))},
                                      {"name", found.value->name},
                                      {"displayName", found.value->display_name.empty() ? found.value->name : found.value->display_name}};
    boost::json::array algorithms;
    for (const auto alg : {webauthn::kEs256, webauthn::kEdDsa, webauthn::kRs256})
      algorithms.push_back(boost::json::object{{"type", "public-key"}, {"alg", alg}});
    out["pubKeyCredParams"] = std::move(algorithms);
    out["authenticatorSelection"] = boost::json::object{{"residentKey", "required"}, {"requireResidentKey", true}, {"userVerification", "required"}};
    out["attestation"] = "none";
    shared->factors->webauthn_credentials(user_id, kRouteDeadline, context.executor, [context, out](Outcome<std::vector<std::string>> ids) mutable {
      if (!ids.ok()) return answer_fault(context, ids);
      out["excludeCredentials"] = credential_list(ids.value);
      answer_json(context, http::status::ok, out);
    });
  });
}

// A TOTP code or a WebAuthn assertion, proved through the authenticator, which backs off and
// audits as at sign-in; on success the window opens.
void reauthenticate(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session) return;
  const auto body = body_object(context, {"code", "webauthn"});
  if (!body) return context.done();
  const auto* code = body->if_contains("code");
  const auto* assertion = body->if_contains("webauthn");
  if ((code == nullptr) == (assertion == nullptr)) return answer_error(context, http::status::bad_request, "invalid", "send a code, or a webauthn assertion");

  const auto sid = session->sid;
  const auto windows = shared->windows;
  const auto answered = [context, windows, sid](Step step) {
    switch (step.kind) {
      case Step::Kind::next: {
        windows->open(sid);
        return answer_json(context, http::status::ok, boost::json::object{{"expires_in", windows->window().count()}});
      }
      case Step::Kind::wait:
        http::Router::write_too_many(context.response, step.retry_after);
        return context.done();
      case Step::Kind::failed:
        return answer_fault(context, Outcome<>::failure(Fault::failed, "not now"));
      case Step::Kind::refused:
      case Step::Kind::ended:
        break;
    }
    answer_error(context, http::status::forbidden, "refused", "that did not prove one of your factors");
  };

  if (code != nullptr) {
    if (!code->is_string()) return answer_error(context, http::status::bad_request, "invalid", "code must be a string");
    return shared->authenticator->reauthenticate_totp(session->user_id, std::string(code->as_string()), context.remote, kRouteDeadline, context.executor,
                                                      answered);
  }

  if (!offered(*shared, context)) return;
  if (!assertion->is_object()) return answer_error(context, http::status::bad_request, "invalid", "webauthn must be an object");
  const auto& parts = assertion->as_object();
  const auto challenge = bytes_member(parts, "challenge");
  const auto id = bytes_member(parts, "id");
  const auto client_data = bytes_member(parts, "client_data");
  const auto authenticator_data = bytes_member(parts, "authenticator_data");
  const auto signature = bytes_member(parts, "signature");
  if (!challenge || !id || !client_data || !authenticator_data || !signature)
    return answer_error(context, http::status::bad_request, "invalid",
                        "webauthn carries challenge, id, client_data, authenticator_data and signature, each base64url");
  const auto& settings = *shared->webauthn;
  const auto claimed = text_of(*challenge);
  if (!settings.challenges->claim(claimed, binding_of(*session)))
    return answer_error(context, http::status::forbidden, "refused", "that challenge has expired or was used already");
  shared->authenticator->reauthenticate_webauthn(session->user_id, text_of(*id), expected_of(settings, claimed), *client_data, *authenticator_data, *signature,
                                                 context.remote, kRouteDeadline, context.executor,
                                                 [answered, challenges = settings.challenges, claimed](Step step) {
                                                   // Only a ceremony that succeeded keeps its challenge used.
                                                   if (step.kind != Step::Kind::next) challenges->release(claimed);
                                                   answered(std::move(step));
                                                 });
}

void list_factors(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session) return;
  shared->factors->list(session->user_id, kRouteDeadline, context.executor, [context](Outcome<std::vector<authn::FactorInfo>> found) {
    if (!found.ok()) return answer_fault(context, found);
    answer_factors(context, found.value);
  });
}

void totp_begin(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session || !window_open(*shared, context, *session)) return;
  if (!body_object(context, {})) return context.done();
  const auto user_id = session->user_id;
  shared->directory->user(user_id, kRouteDeadline, context.executor, [shared, context, user_id](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer_fault(context, found);
    if (!found.value) return answer_fault(context, Outcome<>::failure(Fault::not_found, "no such user"));
    shared->factors->totp_begin(actor_of(context), user_id, shared->totp_issuer, found.value->name, kRouteDeadline, context.executor,
                                [context](Outcome<authn::TotpSetup> made) {
                                  if (!made.ok()) return answer_fault(context, made);
                                  // The secret leaves here once, to its owner, under Cache-Control: no-store.
                                  answer_json(context, http::status::created,
                                              boost::json::object{{"id", factor_id(made.value.factor_id)},
                                                                  {"secret", std::string(secret_text(made.value.secret))},
                                                                  {"uri", std::string(secret_text(made.value.uri))}});
                                });
  });
}

void totp_confirm(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session || !window_open(*shared, context, *session)) return;
  const auto body = body_object(context, {"code"});
  std::optional<std::string> code;
  if (!body || !string_member(context, *body, "code", code)) return context.done();
  if (!code) return answer_error(context, http::status::bad_request, "invalid", "code is required");
  const auto key = factor_key(session->user_id, context.parameter("factor"));
  if (key.empty()) return answer_error(context, http::status::not_found, "not_found", "no such factor");
  shared->factors->totp_confirm(actor_of(context), session->user_id, key, *code, kRouteDeadline, context.executor, [context](Outcome<> confirmed) {
    if (!confirmed.ok()) return answer_fault(context, confirmed);
    http::write_no_content(context.response);
    context.done();
  });
}

void webauthn_register(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  if (!offered(*shared, context)) return;
  const auto session = own(*shared, context);
  if (!session || !window_open(*shared, context, *session)) return;
  const auto body = body_object(context, {"name", "challenge", "client_data", "attestation_object"});
  std::optional<std::string> name;
  if (!body || !string_member(context, *body, "name", name)) return context.done();
  const auto challenge = bytes_member(*body, "challenge");
  const auto client_data = bytes_member(*body, "client_data");
  const auto attestation = bytes_member(*body, "attestation_object");
  if (!challenge || !client_data || !attestation)
    return answer_error(context, http::status::bad_request, "invalid", "challenge, client_data and attestation_object are required, each base64url");
  const auto& settings = *shared->webauthn;
  const auto claimed = text_of(*challenge);
  if (!settings.challenges->claim(claimed, binding_of(*session)))
    return answer_error(context, http::status::forbidden, "refused", "that challenge has expired or was used already");
  auto expected = expected_of(settings, claimed);
  // A passkey, as at enrolment: it may sign in alone, so the user must have been verified.
  expected.user_verification = true;
  shared->factors->webauthn_register(actor_of(context), session->user_id, name.value_or("Passkey"), std::move(expected), *client_data, *attestation,
                                     kRouteDeadline, context.executor,
                                     [context, challenges = settings.challenges, claimed](Outcome<authn::FactorInfo> registered) {
                                       if (!registered.ok()) {
                                         challenges->release(claimed);
                                         return answer_fault(context, registered);
                                       }
                                       answer_json(context, http::status::created, factor_json(registered.value));
                                     });
}

void rename_credential(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session || !window_open(*shared, context, *session)) return;
  const auto body = body_object(context, {"name"});
  std::optional<std::string> name;
  if (!body || !string_member(context, *body, "name", name)) return context.done();
  if (!name) return answer_error(context, http::status::bad_request, "invalid", "name is required");
  const auto key = factor_key(session->user_id, context.parameter("factor"));
  if (key.empty()) return answer_error(context, http::status::not_found, "not_found", "no such factor");
  shared->factors->webauthn_rename(actor_of(context), session->user_id, key, *name, kRouteDeadline, context.executor,
                                   [context](Outcome<authn::FactorInfo> renamed) {
                                     if (!renamed.ok()) return answer_fault(context, renamed);
                                     answer_json(context, http::status::ok, factor_json(renamed.value));
                                   });
}

void remove_factor(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session || !window_open(*shared, context, *session)) return;
  const auto key = factor_key(session->user_id, context.parameter("factor"));
  if (key.empty()) return answer_error(context, http::status::not_found, "not_found", "no such factor");
  shared->authenticator->remove_factor(actor_of(context), session->user_id, key, kRouteDeadline, context.executor, [context](Outcome<> removed) {
    if (!removed.ok()) return answer_fault(context, removed);
    http::write_no_content(context.response);
    context.done();
  });
}

void new_recovery_codes(const std::shared_ptr<Shared>& shared, const RouteContext& context) {
  const auto session = own(*shared, context);
  if (!session || !window_open(*shared, context, *session)) return;
  if (!body_object(context, {})) return context.done();
  shared->factors->recovery_generate(actor_of(context), session->user_id, kRouteDeadline, context.executor, [context](Outcome<std::vector<Secret>> made) {
    if (!made.ok()) return answer_fault(context, made);
    boost::json::array codes;
    for (const auto& code : made.value) codes.push_back(boost::json::string(secret_text(code)));
    answer_json(context, http::status::created, boost::json::object{{"codes", std::move(codes)}});
  });
}

}  // namespace

void FactorRoutes::register_routes(http::Router& router) {
  using http::verb;
  const auto shared = _shared;
  const auto bind = [shared](void (*handler)(const std::shared_ptr<Shared>&, const RouteContext&)) {
    return [shared, handler](RouteContext context) { handler(shared, context); };
  };
  router.add_authenticated(verb::get, "/api/v1/me/factors", bind(&list_factors));
  router.add_authenticated(verb::post, "/api/v1/me/webauthn/options", bind(&options));
  router.add_authenticated(verb::post, "/api/v1/me/reauthenticate", bind(&reauthenticate));
  router.add_authenticated(verb::post, "/api/v1/me/factors/totp", bind(&totp_begin));
  router.add_authenticated(verb::post, "/api/v1/me/factors/totp/{factor}/confirm", bind(&totp_confirm));
  router.add_authenticated(verb::post, "/api/v1/me/factors/webauthn", bind(&webauthn_register));
  router.add_authenticated(verb::post, "/api/v1/me/factors/recovery", bind(&new_recovery_codes));
  router.add_authenticated(verb::patch, "/api/v1/me/factors/{factor}", bind(&rename_credential));
  router.add_authenticated(verb::delete_, "/api/v1/me/factors/{factor}", bind(&remove_factor));
}

}  // namespace lugh::api

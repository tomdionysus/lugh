//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/signin/pages.h"

#include <map>
#include <optional>
#include <string>

#include "lugh/core/encoding.h"
#include "lugh/http/api_json.h"
#include "lugh/http/forms.h"
#include "lugh/signin/html.h"
#include "lugh/signin/qr.h"

namespace lugh::signin {

using authn::SignIn;
using authn::Step;
using http::RouteContext;
using session::PreSession;
using session::PreSessions;
using session::Sessions;
using Form = std::map<std::string, std::string>;

struct Pages::Shared {
  std::shared_ptr<authn::Authenticator> authenticator;
  std::shared_ptr<directory::Directory> directory;
  std::shared_ptr<Sessions> sessions;
  std::shared_ptr<PreSessions> pre;
  std::optional<Pages::WebAuthn> webauthn;
};

namespace {

// Argon2id runs on the hashing pool; a page waits no longer than this for it and the store.
constexpr Deadline kPageDeadline = std::chrono::seconds(15);
// The visitor cookie outlives a sign-in comfortably; it names nothing until a password is in.
constexpr long kVisitorSeconds = 3600;

std::string field(const Form& form, const std::string& name) {
  const auto found = form.find(name);
  return found == form.end() ? std::string() : found->second;
}

std::string csrf_field(const std::string& token) { return "<input type=\"hidden\" name=\"csrf\" value=\"" + escape(token) + "\">\n"; }

std::string notice(const std::string& text, bool warning = false) {
  if (text.empty()) return {};
  return std::string("<p class=\"notice") + (warning ? " warn" : "") + "\" role=\"alert\">" + escape(text) + "</p>\n";
}

// What the dashboard sends as `continue` to come back to itself after a sign-in or a step-up.
constexpr const char* kDashboard = "dashboard";

// An authorisation request's id, as the sign-in carries it: base64url, as Lugh makes them.
std::string resume_of(const std::string& text) {
  if (text.empty() || text.size() > 64) return {};
  const bool ok = std::all_of(text.begin(), text.end(),
                              [](char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'; });
  return ok ? text : std::string();
}

// Where a finished sign-in goes: back to the authorisation request waiting on it, or to the
// signed-in page.
std::string done_target(const std::string& resume) {
  if (resume.empty()) return "/signin/done";
  // The dashboard (P7), served at the root; a fixed word, so the sign-in names no other place.
  if (resume == kDashboard) return "/";
  // A device's user signing in on the way to approving it (RFC 8628).
  if (resume.rfind("device-", 0) == 0) return "/signin/device?user_code=" + resume.substr(7);
  return "/oauth2/authorize/resume?id=" + resume;
}

// The page head that loads the WebAuthn script, when WebAuthn is offered.
std::string script_head(bool webauthn) { return webauthn ? "<script src=\"/signin/webauthn.js\" defer></script>\n" : ""; }

// A WebAuthn ceremony's button, hidden until the script finds the browser can run one, and the
// form the script fills with the ceremony's result and posts.
std::string webauthn_parts(bool webauthn, const std::string& csrf, const std::string& purpose, const std::string& label, const std::string& resume = "") {
  if (!webauthn) return {};
  std::string out = "<div class=\"alternative\">\n";
  if (purpose == "enrol") {
    out +=
        "<label for=\"key_name\">Or add a passkey or security key, named</label>\n"
        "<input id=\"key_name\" type=\"text\" maxlength=\"64\" value=\"Passkey\" autocomplete=\"off\">\n";
  }
  out += "<button type=\"button\" data-webauthn=\"" + escape(purpose) + "\" hidden>" + escape(label) + "</button>\n";
  out += "<p class=\"notice warn\" id=\"webauthn-status\" role=\"alert\" hidden></p>\n";
  out += "<form id=\"webauthn\" method=\"post\" action=\"/signin/webauthn\" hidden>\n" + csrf_field(csrf);
  if (!resume.empty()) out += "<input type=\"hidden\" name=\"continue\" value=\"" + escape(resume) + "\">\n";
  for (const char* name : {"purpose", "challenge", "id", "client_data", "authenticator_data", "signature", "user_handle", "attestation_object", "name"})
    out += std::string("<input type=\"hidden\" name=\"") + name + "\">\n";
  out += "</form>\n</div>\n";
  return out;
}

// The level an application asked for, as the sign-in carries it: an acr Lugh knows, or nothing.
// It only raises what the sign-in requires, so one a visitor writes can make it no weaker.
std::string wanted_of(const std::string& text) { return authn::assurance_from_acr(text) ? text : std::string(); }

std::string password_form(const std::string& csrf, const std::string& warning, const std::string& login, const std::string& resume = "", bool webauthn = false,
                          const std::string& wanted = "") {
  auto carried = resume.empty() ? std::string() : "<input type=\"hidden\" name=\"continue\" value=\"" + escape(resume) + "\">\n";
  if (!wanted.empty()) carried += "<input type=\"hidden\" name=\"acr\" value=\"" + escape(wanted) + "\">\n";
  const bool phr = authn::assurance_from_acr(wanted) == authn::Assurance::phr;
  return notice(phr ? "This needs your passkey or security key." : "") + notice(warning) + "<form method=\"post\" action=\"/signin\">\n" + csrf_field(csrf) +
         carried +
         "<label for=\"login\">Name or email</label>\n"
         "<input id=\"login\" name=\"login\" type=\"text\" autocomplete=\"username webauthn\" autocapitalize=\"none\" spellcheck=\"false\" required value=\"" +
         escape(login) +
         "\">\n"
         "<label for=\"password\">Password</label>\n"
         "<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>\n"
         "<button type=\"submit\">Sign in</button>\n"
         "</form>\n" +
         webauthn_parts(webauthn, csrf, "passkey", "Sign in with a passkey", resume);
}

std::string factor_form(const std::string& csrf, const std::string& warning, bool webauthn = false, bool phr = false) {
  // phr wanted: a code will not do, so none is asked for.
  if (phr) {
    if (!webauthn) return notice(warning) + notice("This needs a passkey or security key, which this server does not offer.", true);
    return notice(warning) + notice("This needs your passkey or security key.") + webauthn_parts(webauthn, csrf, "factor", "Use your passkey or security key");
  }
  return notice(warning) + webauthn_parts(webauthn, csrf, "factor", "Use your passkey or security key") + "<form method=\"post\" action=\"/signin/factor\">\n" +
         csrf_field(csrf) +
         "<label for=\"code\">Code from your authenticator app</label>\n"
         "<input id=\"code\" name=\"code\" type=\"text\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9 ]*\" required>\n"
         "<button type=\"submit\">Continue</button>\n"
         "</form>\n"
         "<form class=\"alternative\" method=\"post\" action=\"/signin/factor\">\n" +
         csrf_field(csrf) +
         "<label for=\"recovery\">Or a recovery code</label>\n"
         "<input id=\"recovery\" name=\"recovery\" type=\"text\" autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" required>\n"
         "<button type=\"submit\">Use a recovery code</button>\n"
         "</form>\n";
}

std::string set_password_form(const std::string& csrf, const std::string& token, const std::string& warning) {
  return notice(warning) +
         "<p class=\"muted\">Choose a password of at least 12 characters, not your name or address, and not one used elsewhere.</p>\n"
         "<form method=\"post\" action=\"/signin/enrol/" +
         escape(token) + "\">\n" + csrf_field(csrf) +
         "<label for=\"password\">New password</label>\n"
         "<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\" required>\n"
         "<label for=\"password_again\">The same again</label>\n"
         "<input id=\"password_again\" name=\"password_again\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\" required>\n"
         "<button type=\"submit\">Set password</button>\n"
         "</form>\n";
}

std::string text_of(const SecureBuffer& buffer) { return std::string(buffer.begin(), buffer.end()); }

std::string grouped(const std::string& secret) {
  std::string out;
  for (std::size_t i = 0; i < secret.size(); ++i) {
    if (i > 0 && i % 4 == 0) out.push_back(' ');
    out.push_back(secret[i]);
  }
  return out;
}

std::string totp_form(const std::string& csrf, const PreSession& pre, const std::string& warning, bool webauthn = false) {
  const auto code = qr_encode(text_of(pre.totp_uri));
  return notice(warning) +
         "<p>Scan this with your authenticator app, or add the key below by hand, then type the code it shows. Every sign-in after this needs the password and "
         "a "
         "code.</p>\n" +
         (code ? qr_svg(*code, "A QR code holding your authenticator key") + "\n" : std::string()) + "<p class=\"secret\">" +
         escape(grouped(text_of(pre.totp_secret))) +
         "</p>\n"
         "<p class=\"muted\">Or open this in the app: <span class=\"secret\">" +
         escape(text_of(pre.totp_uri)) +
         "</span></p>\n"
         "<form method=\"post\" action=\"/signin/enrol/totp\">\n" +
         csrf_field(csrf) +
         "<label for=\"code\">Code from your authenticator app</label>\n"
         "<input id=\"code\" name=\"code\" type=\"text\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required>\n"
         "<button type=\"submit\">Confirm</button>\n"
         "</form>\n" +
         webauthn_parts(webauthn, csrf, "enrol", "Add a passkey or security key");
}

std::string recovery_page(const std::vector<Secret>& codes, const std::string& next) {
  std::string list;
  for (const auto& code : codes) list += "<li class=\"secret\">" + escape(secret_text(code)) + "</li>\n";
  return page("Your recovery codes",
              "<p>You are signed in. Keep these somewhere safe: each lets you in once if you lose your authenticator app. They are shown "
              "this once.</p>\n<ul class=\"codes\">\n" +
                  list + "</ul>\n<p><a href=\"" + escape(next) + "\">I have kept them</a></p>\n");
}

std::string message(const std::string& title, const std::string& text, const std::string& link = "/signin", const std::string& link_text = "Sign in") {
  return page(title, "<p>" + escape(text) + "</p>\n<p><a href=\"" + escape(link) + "\">" + escape(link_text) + "</a></p>\n");
}

// The visitor's handle: the cookie's, or a new one, set on the response.
std::string visitor(const RouteContext& context) {
  if (const auto handle = http::cookie(*context.request, PreSessions::kCookie); handle && PreSessions::handle_ok(*handle)) return *handle;
  auto fresh = PreSessions::new_handle();
  context.response->insert(http::field::set_cookie, http::host_cookie(PreSessions::kCookie, fresh, kVisitorSeconds));
  return fresh;
}

// The posted form, checked: the body is a form and carries the visitor's CSRF token.
// Nothing, having answered, otherwise.
std::optional<Form> posted(const RouteContext& context, const PreSessions& pre, const std::string& handle) {
  auto form = http::parse_form(context.body());
  if (!form) {
    write_page(context.response, http::status::bad_request, message("Something was wrong", "That form could not be read. Start again."));
    context.done();
    return std::nullopt;
  }
  if (!pre.csrf_ok(handle, field(*form, "csrf"))) {
    write_page(context.response, http::status::forbidden, message("Start again", "That form has expired, or came from another site. Start again."));
    context.done();
    return std::nullopt;
  }
  return form;
}

void answer_page(const RouteContext& context, http::status status, const std::string& html) {
  write_page(context.response, status, html);
  context.done();
}

void answer_redirect(const RouteContext& context, const std::string& location) {
  write_redirect(context.response, location);
  context.done();
}

void failed(const RouteContext& context) {
  answer_page(context, http::status::internal_server_error, message("Not now", "Signing in could not be completed. Try again in a moment."));
}

void waiting(const RouteContext& context, const Step& step) {
  const auto seconds = step.retry_after.count();
  context.response->set(http::field::retry_after, std::to_string(seconds));
  answer_page(context, http::status::too_many_requests,
              message("Too many tries", "Wait " + std::to_string(seconds) + (seconds == 1 ? " second" : " seconds") + ", then try again."));
}

// The user is signed in: a session, its cookie, and the sign-in in progress gone.
void complete(const std::shared_ptr<Pages::Shared>& shared, const RouteContext& context, const std::string& handle, Step step, const std::string& resume) {
  const auto& sign_in = step.sign_in;
  auto codes = std::make_shared<std::vector<Secret>>(std::move(step.recovery_codes));
  const auto left = step.recovery_left;
  shared->sessions->create(
      audit::Actor{sign_in.user_id, context.remote}, sign_in.user_id, sign_in.reached, sign_in.amr, kPageDeadline, context.executor,
      [shared, context, handle, codes, left, next = done_target(resume)](Outcome<Sessions::Created> made) {
        if (!made.ok()) return failed(context);
        shared->pre->end(handle);
        const auto lifetime = shared->sessions->settings().absolute.count();
        context.response->insert(http::field::set_cookie, http::host_cookie(Sessions::kCookie, secret_text(made.value.handle), static_cast<long>(lifetime)));
        if (!codes->empty()) return answer_page(context, http::status::ok, recovery_page(*codes, next));
        if (left) {
          return answer_page(
              context, http::status::ok,
              message("Signed in",
                      "That recovery code is used. You have " + std::to_string(*left) + " left: make new ones, or enrol a new authenticator app, soon.", next,
                      "Continue"));
        }
        answer_redirect(context, next);
      });
}

// Where a step leads: the next page, the session, or the same form again with why.
void advance(const std::shared_ptr<Pages::Shared>& shared, const RouteContext& context, const std::string& handle, Step step, const std::string& resume,
             std::function<void(const std::string& warning)> again) {
  switch (step.kind) {
    case Step::Kind::refused:
      return again("");
    case Step::Kind::wait:
      return waiting(context, step);
    case Step::Kind::failed:
      return failed(context);
    case Step::Kind::ended: {
      shared->pre->end(handle);
      const bool webauthn = shared->webauthn.has_value();
      return answer_page(
          context, http::status::unauthorized,
          page("Sign in",
               password_form(shared->pre->csrf_token(handle), "Start again: there were too many wrong codes, or it took too long.", "", resume, webauthn),
               script_head(webauthn)));
    }
    case Step::Kind::next:
      break;
  }
  switch (step.sign_in.stage) {
    case SignIn::Stage::second_factor:
      shared->pre->put(handle, PreSession{step.sign_in, {}, {}, {}, resume});
      return answer_redirect(context, "/signin/factor");
    case SignIn::Stage::enrolment:
      shared->pre->put(handle, PreSession{step.sign_in, {}, {}, {}, resume});
      return answer_redirect(context, "/signin/enrol/totp");
    case SignIn::Stage::complete:
      return complete(shared, context, handle, std::move(step), resume);
    case SignIn::Stage::ended:
      break;
  }
  failed(context);
}

}  // namespace

Pages::Pages(std::shared_ptr<authn::Authenticator> authenticator, std::shared_ptr<directory::Directory> directory, std::shared_ptr<Sessions> sessions,
             std::shared_ptr<PreSessions> pre_sessions)
    : _shared(std::make_shared<Shared>(Shared{std::move(authenticator), std::move(directory), std::move(sessions), std::move(pre_sessions), std::nullopt})) {}

void Pages::webauthn(WebAuthn settings) { _shared->webauthn = std::move(settings); }

namespace {

// The result's pages are drawn only when WebAuthn is offered, so they always offer it.
constexpr bool kOffered = true;

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

boost::json::array credential_list(const std::vector<std::string>& ids) {
  boost::json::array out;
  for (const auto& id : ids) out.push_back(boost::json::object{{"type", "public-key"}, {"id", encoding::base64url(bytes_of(id))}});
  return out;
}

void answer_json(const RouteContext& context, http::status status, const boost::json::value& value) {
  http::write_json(context.response, status, value);
  context.done();
}

void answer_json_error(const RouteContext& context, http::status status, std::string code, std::string message) {
  http::write_error(context.response, status, std::move(code), std::move(message));
  context.done();
}

// The options for a ceremony (W3C WebAuthn 5.4 and 5.5), for the visitor this sign-in is.
void webauthn_options(const std::shared_ptr<Pages::Shared>& shared, const RouteContext& context) {
  if (!shared->webauthn) return answer_json_error(context, http::status::not_found, "not_found", "WebAuthn is not offered here");
  const auto& settings = *shared->webauthn;
  const auto handle = visitor(context);
  if (!shared->pre->csrf_ok(handle, std::string((*context.request)["X-CSRF-Token"])))
    return answer_json_error(context, http::status::forbidden, "forbidden", "start again: the sign-in has expired or came from another site");
  const auto body = http::parse_object(context.body());
  const auto* purpose = body ? body->if_contains("purpose") : nullptr;
  if (!purpose || !purpose->is_string()) return answer_json_error(context, http::status::bad_request, "invalid", "purpose is passkey, factor or enrol");

  boost::json::object options;
  options["challenge"] = encoding::base64url(bytes_of(settings.challenges->issue(handle)));
  options["timeout"] = 300000;

  if (purpose->as_string() == "passkey") {
    options["rpId"] = settings.rp_id;
    options["userVerification"] = "required";
    options["allowCredentials"] = boost::json::array{};
    return answer_json(context, http::status::ok, options);
  }

  const auto pre = shared->pre->find(handle);
  if (purpose->as_string() == "factor") {
    if (!pre || pre->sign_in.stage != SignIn::Stage::second_factor) return answer_json_error(context, http::status::conflict, "conflict", "start again");
    options["rpId"] = settings.rp_id;
    options["userVerification"] = "preferred";
    return settings.factors->webauthn_credentials(pre->sign_in.user_id, kPageDeadline, context.executor,
                                                  [context, options](Outcome<std::vector<std::string>> ids) mutable {
                                                    if (!ids.ok()) return answer_json_error(context, http::status::internal_server_error, "failed", "not now");
                                                    options["allowCredentials"] = credential_list(ids.value);
                                                    answer_json(context, http::status::ok, options);
                                                  });
  }

  if (purpose->as_string() == "enrol") {
    if (!pre || pre->sign_in.stage != SignIn::Stage::enrolment) return answer_json_error(context, http::status::conflict, "conflict", "start again");
    const auto user_id = pre->sign_in.user_id;
    return shared->directory->user(
        user_id, kPageDeadline, context.executor, [shared, context, options, user_id](Outcome<std::optional<directory::User>> found) mutable {
          if (!found.ok() || !found.value) return answer_json_error(context, http::status::internal_server_error, "failed", "not now");
          const auto& offered = *shared->webauthn;
          options["rp"] = boost::json::object{{"id", offered.rp_id}, {"name", offered.rp_name}};
          // The user handle is the immutable id: nothing a person would recognise, and never their
          // name or address (WebAuthn 14.6.1).
          options["user"] = boost::json::object{{"id", encoding::base64url(bytes_of(user_id))},
                                                {"name", found.value->name},
                                                {"displayName", found.value->display_name.empty() ? found.value->name : found.value->display_name}};
          boost::json::array algorithms;
          for (const auto alg : {webauthn::kEs256, webauthn::kEdDsa, webauthn::kRs256})
            algorithms.push_back(boost::json::object{{"type", "public-key"}, {"alg", alg}});
          options["pubKeyCredParams"] = std::move(algorithms);
          // A passkey: discoverable, so it signs in with no name typed, and verifying the user.
          options["authenticatorSelection"] = boost::json::object{{"residentKey", "required"}, {"requireResidentKey", true}, {"userVerification", "required"}};
          options["attestation"] = "none";
          offered.factors->webauthn_credentials(user_id, kPageDeadline, context.executor, [context, options](Outcome<std::vector<std::string>> ids) mutable {
            if (!ids.ok()) return answer_json_error(context, http::status::internal_server_error, "failed", "not now");
            options["excludeCredentials"] = credential_list(ids.value);
            answer_json(context, http::status::ok, options);
          });
        });
  }
  answer_json_error(context, http::status::bad_request, "invalid", "purpose is passkey, factor or enrol");
}

// A ceremony's result, posted by the script as a form: the challenge claimed for this visitor,
// the authenticator's step, and the page it leads to. A step that fails gives the challenge back.
void webauthn_result(const std::shared_ptr<Pages::Shared>& shared, const RouteContext& context) {
  const auto handle = visitor(context);
  const auto form = posted(context, *shared->pre, handle);
  if (!form) return;
  if (!shared->webauthn) return answer_page(context, http::status::not_found, message("Not here", "WebAuthn is not offered here."));
  const auto settings = *shared->webauthn;
  const auto decoded = [&](const std::string& name) {
    const auto bytes = encoding::base64url_decode(field(*form, name));
    return bytes ? *bytes : Bytes{};
  };
  const auto challenge_bytes = decoded("challenge");
  const std::string challenge(challenge_bytes.begin(), challenge_bytes.end());
  const auto purpose = field(*form, "purpose");
  const auto start_again = [&] {
    answer_page(context, http::status::unauthorized, message("Start again", "That took too long, or was used already. Start again."));
  };
  if (!settings.challenges->claim(challenge, handle)) return start_again();

  webauthn::Expected expected;
  expected.rp_id = settings.rp_id;
  expected.origins = settings.origins;
  expected.challenge = challenge;
  const auto id_bytes = decoded("id");
  const std::string credential_id(id_bytes.begin(), id_bytes.end());
  // A step that did not succeed gives back its challenge, so only ceremonies that did stay used.
  const auto keeping = [challenges = settings.challenges, challenge](Step& step) {
    if (step.kind != Step::Kind::next) challenges->release(challenge);
  };

  if (purpose == "passkey") {
    const auto user_bytes = decoded("user_handle");
    const auto resume = resume_of(field(*form, "continue"));
    return shared->authenticator->passkey(
        std::string(user_bytes.begin(), user_bytes.end()), credential_id, expected, decoded("client_data"), decoded("authenticator_data"), decoded("signature"),
        context.remote, kPageDeadline, context.executor, [shared, context, handle, resume, keeping](Step step) {
          keeping(step);
          advance(shared, context, handle, std::move(step), resume, [&](const std::string&) {
            answer_page(context, http::status::unauthorized,
                        page("Sign in", password_form(shared->pre->csrf_token(handle), "That passkey did not sign you in.", "", resume, kOffered),
                             script_head(kOffered)));
          });
        });
  }

  const auto pre = shared->pre->find(handle);
  if (purpose == "factor") {
    if (!pre || pre->sign_in.stage != SignIn::Stage::second_factor) {
      settings.challenges->release(challenge);
      return answer_redirect(context, "/signin");
    }
    return shared->authenticator->webauthn(
        pre->sign_in, credential_id, expected, decoded("client_data"), decoded("authenticator_data"), decoded("signature"), context.remote, kPageDeadline,
        context.executor, [shared, context, handle, resume = pre->resume, keeping](Step step) {
          keeping(step);
          const auto sign_in = step.sign_in;
          advance(shared, context, handle, std::move(step), resume, [&](const std::string&) {
            shared->pre->put(handle, PreSession{sign_in, {}, {}, {}, resume});
            answer_page(context, http::status::unauthorized,
                        page("Your second factor",
                             factor_form(shared->pre->csrf_token(handle), "That key did not sign you in.", kOffered, sign_in.required == authn::Assurance::phr),
                             script_head(kOffered)));
          });
        });
  }

  if (purpose == "enrol") {
    if (!pre || pre->sign_in.stage != SignIn::Stage::enrolment) {
      settings.challenges->release(challenge);
      return answer_redirect(context, "/signin");
    }
    expected.user_verification = true;
    auto name = field(*form, "name");
    if (name.empty()) name = "Passkey";
    return shared->authenticator->enrol_webauthn(
        pre->sign_in, std::move(name), expected, decoded("client_data"), decoded("attestation_object"), context.remote, kPageDeadline, context.executor,
        [shared, context, handle, held = *pre, keeping](Step step) {
          keeping(step);
          auto next = held;
          next.sign_in = step.sign_in;
          advance(shared, context, handle, std::move(step), held.resume, [&](const std::string&) {
            shared->pre->put(handle, next);
            answer_page(context, http::status::unauthorized,
                        page("Add your authenticator", totp_form(shared->pre->csrf_token(handle), next, "That key could not be added.", kOffered),
                             script_head(kOffered)));
          });
        });
  }

  settings.challenges->release(challenge);
  answer_page(context, http::status::bad_request, message("Something was wrong", "That form could not be read. Start again."));
}

}  // namespace

void Pages::register_routes(http::Router& router) {
  using http::verb;
  const auto shared = _shared;

  router.add_open(verb::get, "/signin/style.css", [](RouteContext context) {
    context.response->result(http::status::ok);
    context.response->set(http::field::content_type, "text/css; charset=utf-8");
    context.response->set(http::field::cache_control, "public, max-age=3600");
    context.response->body() = std::string(stylesheet());
    context.done();
  });

  router.add_open(verb::get, "/signin", [shared](RouteContext context) {
    const auto resume = resume_of(context.query.count("continue") ? context.query.at("continue") : "");
    // Signed in already, and nothing waiting that asked for a new sign-in: nothing to do here.
    if (const auto handle = http::cookie(*context.request, Sessions::kCookie); resume.empty() && handle && shared->sessions->find(*handle)) {
      return answer_redirect(context, "/signin/done");
    }
    const auto handle = visitor(context);
    const bool webauthn = shared->webauthn.has_value();
    const auto wanted = wanted_of(context.query.count("acr") ? context.query.at("acr") : "");
    answer_page(context, http::status::ok,
                page("Sign in", password_form(shared->pre->csrf_token(handle), "", "", resume, webauthn, wanted), script_head(webauthn)));
  });

  router.add_open(verb::post, "/signin", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto form = posted(context, *shared->pre, handle);
    if (!form) return;
    const auto login = field(*form, "login");
    const auto resume = resume_of(field(*form, "continue"));
    const auto wanted = wanted_of(field(*form, "acr"));
    const auto at_least = authn::assurance_from_acr(wanted).value_or(authn::Assurance::pwd);
    shared->authenticator->password(
        login, text_secret(field(*form, "password")), context.remote, kPageDeadline, context.executor,
        [shared, context, handle, login, resume, wanted](Step step) {
          advance(shared, context, handle, std::move(step), resume, [&](const std::string&) {
            const bool webauthn = shared->webauthn.has_value();
            answer_page(context, http::status::unauthorized,
                        page("Sign in", password_form(shared->pre->csrf_token(handle), "That name and password do not match.", login, resume, webauthn, wanted),
                             script_head(webauthn)));
          });
        },
        at_least);
  });

  router.add_open(verb::get, "/signin/factor", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto pre = shared->pre->find(handle);
    if (!pre || pre->sign_in.stage != SignIn::Stage::second_factor) return answer_redirect(context, "/signin");
    const bool webauthn = shared->webauthn.has_value();
    const bool phr = pre->sign_in.required == authn::Assurance::phr;
    answer_page(context, http::status::ok, page("Your second factor", factor_form(shared->pre->csrf_token(handle), "", webauthn, phr), script_head(webauthn)));
  });

  router.add_open(verb::post, "/signin/factor", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto form = posted(context, *shared->pre, handle);
    if (!form) return;
    const auto pre = shared->pre->find(handle);
    if (!pre || pre->sign_in.stage != SignIn::Stage::second_factor) return answer_redirect(context, "/signin");
    const auto respond = [shared, context, handle, resume = pre->resume](Step step) {
      // The step carries the sign-in's count of wrong codes, kept for the next try.
      const auto sign_in = step.sign_in;
      advance(shared, context, handle, std::move(step), resume, [&](const std::string&) {
        shared->pre->put(handle, PreSession{sign_in, {}, {}, {}, resume});
        const bool webauthn = shared->webauthn.has_value();
        answer_page(context, http::status::unauthorized,
                    page("Your second factor",
                         factor_form(shared->pre->csrf_token(handle), "That code is not right.", webauthn, sign_in.required == authn::Assurance::phr),
                         script_head(webauthn)));
      });
    };
    if (const auto recovery = field(*form, "recovery"); !recovery.empty()) {
      return shared->authenticator->recovery(pre->sign_in, text_secret(recovery), context.remote, kPageDeadline, context.executor, respond);
    }
    shared->authenticator->totp(pre->sign_in, field(*form, "code"), context.remote, kPageDeadline, context.executor, respond);
  });

  // Before /signin/enrol/{token}, so "totp" is never taken for a token.
  router.add_open(verb::get, "/signin/enrol/totp", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto pre = shared->pre->find(handle);
    if (!pre || pre->sign_in.stage != SignIn::Stage::enrolment) return answer_redirect(context, "/signin");
    shared->authenticator->enrol_begin(
        pre->sign_in, context.remote, kPageDeadline, context.executor,
        [shared, context, handle, sign_in = pre->sign_in, resume = pre->resume](Outcome<authn::TotpSetup> setup) {
          if (!setup.ok()) return failed(context);
          PreSession next{sign_in, setup.value.factor_id, SecureBuffer(setup.value.secret.reveal().begin(), setup.value.secret.reveal().end()),
                          SecureBuffer(setup.value.uri.reveal().begin(), setup.value.uri.reveal().end()), resume};
          shared->pre->put(handle, next);
          const bool webauthn = shared->webauthn.has_value();
          answer_page(context, http::status::ok,
                      page("Add your authenticator", totp_form(shared->pre->csrf_token(handle), next, "", webauthn), script_head(webauthn)));
        });
  });

  router.add_open(verb::post, "/signin/enrol/totp", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto form = posted(context, *shared->pre, handle);
    if (!form) return;
    const auto pre = shared->pre->find(handle);
    if (!pre || pre->sign_in.stage != SignIn::Stage::enrolment || pre->factor_id.empty()) return answer_redirect(context, "/signin");
    shared->authenticator->enrol_confirm(
        pre->sign_in, pre->factor_id, field(*form, "code"), context.remote, kPageDeadline, context.executor, [shared, context, handle, held = *pre](Step step) {
          // The step carries the count of wrong codes, kept for the next try.
          auto next = held;
          next.sign_in = step.sign_in;
          advance(shared, context, handle, std::move(step), held.resume, [&](const std::string&) {
            shared->pre->put(handle, next);
            const bool webauthn = shared->webauthn.has_value();
            answer_page(
                context, http::status::unauthorized,
                page("Add your authenticator", totp_form(shared->pre->csrf_token(handle), next, "That code is not right.", webauthn), script_head(webauthn)));
          });
        });
  });

  router.add_open(verb::get, "/signin/enrol/{token}", [shared](RouteContext context) {
    const auto handle = visitor(context);
    answer_page(context, http::status::ok, page("Set your password", set_password_form(shared->pre->csrf_token(handle), context.parameter("token"), "")));
  });

  router.add_open(verb::post, "/signin/enrol/{token}", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto form = posted(context, *shared->pre, handle);
    if (!form) return;
    const auto token = context.parameter("token");
    const auto again = [shared, context, handle, token](const std::string& warning) {
      answer_page(context, http::status::unauthorized, page("Set your password", set_password_form(shared->pre->csrf_token(handle), token, warning)));
    };
    const auto password = field(*form, "password");
    if (password != field(*form, "password_again")) return again("The two passwords are not the same.");
    shared->authenticator->redeem(text_secret(token), text_secret(password), context.remote, kPageDeadline, context.executor,
                                  [shared, context, handle, again](Step step) {
                                    advance(shared, context, handle, std::move(step), "", [&](const std::string&) {
                                      again(
                                          "That did not work. The link may have been used or have expired, or the password is too short, too common, or "
                                          "your own name or address.");
                                    });
                                  });
  });

  router.add_open(verb::get, "/signin/webauthn.js", [](RouteContext context) {
    context.response->result(http::status::ok);
    context.response->set(http::field::content_type, "text/javascript; charset=utf-8");
    context.response->set(http::field::cache_control, "public, max-age=3600");
    context.response->body() = std::string(webauthn_script());
    context.done();
  });
  router.add_open(verb::post, "/signin/webauthn/options", [shared](RouteContext context) { webauthn_options(shared, context); });
  router.add_open(verb::post, "/signin/webauthn", [shared](RouteContext context) { webauthn_result(shared, context); });

  router.add_open(verb::get, "/signin/done", [shared](RouteContext context) {
    const auto handle = http::cookie(*context.request, Sessions::kCookie);
    const auto session = handle ? shared->sessions->find(*handle) : std::nullopt;
    if (!session) return answer_redirect(context, "/signin");
    shared->directory->user(session->user_id, kPageDeadline, context.executor, [context, session](Outcome<std::optional<directory::User>> user) {
      if (!user.ok() || !user.value) return failed(context);
      const auto& who = user.value->display_name.empty() ? user.value->name : user.value->display_name;
      answer_page(context, http::status::ok,
                  page("Signed in", "<p>You are signed in as <strong>" + escape(who) +
                                        "</strong>.</p>\n"
                                        "<form method=\"post\" action=\"/signout\">\n" +
                                        csrf_field(Sessions::csrf_token(*session)) + "<button type=\"submit\">Sign out</button>\n</form>\n"));
    });
  });

  router.add_open(verb::post, "/signout", [shared](RouteContext context) {
    const auto handle = http::cookie(*context.request, Sessions::kCookie);
    const auto session = handle ? shared->sessions->find(*handle) : std::nullopt;
    const auto form = http::parse_form(context.body());
    const auto signed_out = [context] {
      context.response->insert(http::field::set_cookie, http::host_cookie(Sessions::kCookie, "", 0));
      answer_page(context, http::status::ok, message("Signed out", "You are signed out."));
    };
    if (!session) return signed_out();
    // Signing out is a change: a page on another site must not be able to do it.
    if (!form || !Sessions::csrf_ok(*session, field(*form, "csrf"))) {
      return answer_page(context, http::status::forbidden, message("Not signed out", "That form came from somewhere else.", "/signin/done", "Back"));
    }
    shared->sessions->end(audit::Actor{session->user_id, context.remote}, *handle, kPageDeadline, context.executor, [signed_out, context](Outcome<> ended) {
      if (!ended.ok()) return failed(context);
      signed_out();
    });
  });
}

}  // namespace lugh::signin

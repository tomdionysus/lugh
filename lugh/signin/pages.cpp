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

#include "lugh/http/forms.h"
#include "lugh/signin/html.h"

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
  // A device's user signing in on the way to approving it (RFC 8628).
  if (resume.rfind("device-", 0) == 0) return "/signin/device?user_code=" + resume.substr(7);
  return "/oauth2/authorize/resume?id=" + resume;
}

std::string password_form(const std::string& csrf, const std::string& warning, const std::string& login, const std::string& resume = "") {
  const auto carried = resume.empty() ? std::string() : "<input type=\"hidden\" name=\"continue\" value=\"" + escape(resume) + "\">\n";
  return notice(warning) + "<form method=\"post\" action=\"/signin\">\n" + csrf_field(csrf) + carried +
         "<label for=\"login\">Name or email</label>\n"
         "<input id=\"login\" name=\"login\" type=\"text\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" required value=\"" +
         escape(login) +
         "\">\n"
         "<label for=\"password\">Password</label>\n"
         "<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>\n"
         "<button type=\"submit\">Sign in</button>\n"
         "</form>\n";
}

std::string factor_form(const std::string& csrf, const std::string& warning) {
  return notice(warning) + "<form method=\"post\" action=\"/signin/factor\">\n" + csrf_field(csrf) +
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

std::string totp_form(const std::string& csrf, const PreSession& pre, const std::string& warning) {
  return notice(warning) +
         "<p>Add this key to your authenticator app, then type the code it shows. Every sign-in after this needs the password and a code.</p>\n"
         "<p class=\"secret\">" +
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
         "</form>\n";
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
  context.response->set(http::field::retry_after, std::to_string(step.retry_after.count()));
  answer_page(context, http::status::too_many_requests,
              message("Too many tries", "Wait " + std::to_string(step.retry_after.count()) + " seconds, then try again."));
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
    case Step::Kind::ended:
      shared->pre->end(handle);
      return answer_page(
          context, http::status::unauthorized,
          page("Sign in", password_form(shared->pre->csrf_token(handle), "Start again: there were too many wrong codes, or it took too long.", "", resume)));
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
    : _shared(std::make_shared<Shared>(Shared{std::move(authenticator), std::move(directory), std::move(sessions), std::move(pre_sessions)})) {}

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
    answer_page(context, http::status::ok, page("Sign in", password_form(shared->pre->csrf_token(handle), "", "", resume)));
  });

  router.add_open(verb::post, "/signin", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto form = posted(context, *shared->pre, handle);
    if (!form) return;
    const auto login = field(*form, "login");
    const auto resume = resume_of(field(*form, "continue"));
    shared->authenticator->password(
        login, text_secret(field(*form, "password")), context.remote, kPageDeadline, context.executor, [shared, context, handle, login, resume](Step step) {
          advance(shared, context, handle, std::move(step), resume, [&](const std::string&) {
            answer_page(context, http::status::unauthorized,
                        page("Sign in", password_form(shared->pre->csrf_token(handle), "That name and password do not match.", login, resume)));
          });
        });
  });

  router.add_open(verb::get, "/signin/factor", [shared](RouteContext context) {
    const auto handle = visitor(context);
    const auto pre = shared->pre->find(handle);
    if (!pre || pre->sign_in.stage != SignIn::Stage::second_factor) return answer_redirect(context, "/signin");
    answer_page(context, http::status::ok, page("Your second factor", factor_form(shared->pre->csrf_token(handle), "")));
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
        answer_page(context, http::status::unauthorized, page("Your second factor", factor_form(shared->pre->csrf_token(handle), "That code is not right.")));
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
          answer_page(context, http::status::ok, page("Add your authenticator", totp_form(shared->pre->csrf_token(handle), next, "")));
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
            answer_page(context, http::status::unauthorized,
                        page("Add your authenticator", totp_form(shared->pre->csrf_token(handle), next, "That code is not right.")));
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

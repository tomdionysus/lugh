//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <map>
#include <memory>
#include <string>

#include "dannan/encoding/percent.h"
#include "lugh/api/me_routes.h"
#include "lugh/api/user_routes.h"
#include "lugh/session/pre_sessions.h"
#include "lugh/session/session_callers.h"
#include "lugh/session/sessions.h"
#include "lugh/signin/pages.h"
#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/test/fixtures/route_call.h"

// The sign-in pages, /api/v1/me and /api/v1/users behind one router whose callers are
// sessions, over AuthnRig, and a browser that keeps its cookies between requests.
class SigninRig : public AuthnRig {
 public:
  struct Page {
    unsigned status = 0;
    std::string body;
    std::shared_ptr<lugh::http::HttpResponse> response;

    std::string location() const { return std::string(response->base()[lugh::http::field::location]); }
    std::string header(const std::string& name) const { return std::string(response->base()[name]); }
    // The value of the form's hidden csrf field: what a browser would post back.
    std::string csrf() const { return between("name=\"csrf\" value=\"", "\""); }
    // The TOTP secret shown at enrolment, without the spaces it is shown with.
    std::string totp_secret() const {
      auto secret = between("<p class=\"secret\">", "</p>");
      std::erase(secret, ' ');
      return secret;
    }
    std::string between(const std::string& before, const std::string& after) const {
      const auto start = body.find(before);
      if (start == std::string::npos) return {};
      const auto from = start + before.size();
      return body.substr(from, body.find(after, from) - from);
    }
    bool says(const std::string& text) const { return body.find(text) != std::string::npos; }
  };

  SigninRig() {
    sessions = std::make_shared<lugh::session::Sessions>(store, wall, directory, grants, audit, lugh::session::Sessions::Settings{});
    EXPECT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { sessions->open(kTestDeadline, executor, done); }).ok);
    pre = std::make_shared<lugh::session::PreSessions>(time, std::chrono::minutes(15));
    router = std::make_shared<lugh::http::Router>(io.get_executor(),
                                                  std::make_shared<lugh::http::Throttle>(time, lugh::http::RateLimits{{1000, 1000}, {1000, 1000}}),
                                                  std::make_shared<lugh::session::SessionCallers>(sessions));
    pages = std::make_unique<lugh::signin::Pages>(authenticator, directory, sessions, pre);
    pages->register_routes(*router);
    me = std::make_unique<lugh::api::MeRoutes>(directory, sessions);
    me->register_routes(*router);
    users = std::make_unique<lugh::api::UserRoutes>(directory, factors, authenticator, links);
    users->register_routes(*router);
  }

  // One request as a browser makes it, with its cookies; Set-Cookie answers kept.
  Page request(lugh::http::verb method, const std::string& target, const std::map<std::string, std::string>& form = {},
               std::vector<std::pair<std::string, std::string>> headers = {}) {
    std::string cookie_header;
    for (const auto& [name, value] : jar) cookie_header += (cookie_header.empty() ? "" : "; ") + name + "=" + value;
    if (!cookie_header.empty()) headers.emplace_back("Cookie", cookie_header);
    std::string body;
    for (const auto& [name, value] : form) {
      body += (body.empty() ? "" : "&") + dannan::encoding::percent_encode(name, dannan::encoding::PercentSet::form()) + "=" +
              dannan::encoding::percent_encode(value, dannan::encoding::PercentSet::form());
    }
    if (!form.empty()) headers.emplace_back("Content-Type", "application/x-www-form-urlencoded");

    const char* prefix = target.rfind("/api", 0) == 0 ? "/api" : (target.rfind("/signout", 0) == 0 ? "/signout" : "/signin");
    const auto result = call(io, router->middleware(prefix), method, target, "192.0.2.80", body, headers);
    EXPECT_TRUE(result.answered) << target;

    Page page;
    page.status = static_cast<unsigned>(result.response->result_int());
    page.body = result.response->body();
    page.response = result.response;
    for (const auto& field : result.response->base()) {
      if (field.name() != lugh::http::field::set_cookie) continue;
      const std::string value(field.value());
      const auto equals = value.find('=');
      const auto end = value.find(';');
      const auto name = value.substr(0, equals);
      const auto content = value.substr(equals + 1, end - equals - 1);
      if (value.find("Max-Age=0") != std::string::npos) {
        jar.erase(name);
      } else {
        jar[name] = content;
      }
    }
    return page;
  }

  Page get(const std::string& target) { return request(lugh::http::verb::get, target); }
  Page post(const std::string& target, const std::map<std::string, std::string>& form) { return request(lugh::http::verb::post, target, form); }

  // A password sign-in from the start: the form, then the post with its token.
  Page sign_in(const std::string& login, const std::string& password) {
    const auto form = get("/signin");
    return post("/signin", {{"csrf", form.csrf()}, {"login", login}, {"password", password}});
  }

  boost::asio::io_context io;
  std::shared_ptr<lugh::session::Sessions> sessions;
  std::shared_ptr<lugh::session::PreSessions> pre;
  std::shared_ptr<lugh::http::Router> router;
  std::unique_ptr<lugh::signin::Pages> pages;
  std::unique_ptr<lugh::api::MeRoutes> me;
  std::unique_ptr<lugh::api::UserRoutes> users;
  std::map<std::string, std::string> jar;
};

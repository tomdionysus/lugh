//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/node_browser.h"

// The way into a new cluster, on the real binary over TLS: `lugh-node init` shows root's
// password once; root signs in with it at /signin, goes straight to enrolling an authenticator,
// sees the recovery codes once, and has a session that opens the API, a change through it
// carrying the session's CSRF token.

using namespace node_process;
namespace http = boost::beast::http;

TEST(NodeProcessSignin, RootsFirstSignInOpensTheApi) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto password = root_password(node.made.err);
  ASSERT_FALSE(password.empty()) << node.made.err;

  Serving serving(workspace, node.state, node.credentials);
  ASSERT_TRUE(serving.up()) << serving.log();
  const auto port = serving.port();
  Jar jar;
  const auto as_browser = [&](http::verb method, const std::string& target, const std::string& body = "",
                              std::vector<std::pair<std::string, std::string>> headers = {}) {
    if (jar.header().size()) headers.emplace_back("Cookie", jar.header());
    const bool typed = std::any_of(headers.begin(), headers.end(), [](const auto& one) { return one.first == "Content-Type"; });
    if (!body.empty() && !typed) headers.emplace_back("Content-Type", "application/x-www-form-urlencoded");
    auto reply = send(port, method, target, headers, body);
    if (reply) jar.keep(*reply);
    return reply;
  };

  // Before any sign-in, the API has no caller.
  const auto before = as_browser(http::verb::get, "/api/v1/me");
  ASSERT_TRUE(before);
  EXPECT_EQ(before->status, 401u);

  const auto page = as_browser(http::verb::get, "/signin");
  ASSERT_TRUE(page);
  ASSERT_EQ(page->status, 200u) << page->body;
  EXPECT_NE(page->header("Content-Security-Policy").find("default-src 'none'"), std::string::npos);
  const auto csrf = between(page->body, "name=\"csrf\" value=\"", "\"");
  ASSERT_FALSE(csrf.empty());

  const auto signed_password = as_browser(http::verb::post, "/signin", form({{"csrf", csrf}, {"login", "root"}, {"password", password}}));
  ASSERT_TRUE(signed_password);
  ASSERT_EQ(signed_password->status, 303u) << signed_password->body;
  EXPECT_EQ(signed_password->header("Location"), "/signin/enrol/totp");

  const auto enrol = as_browser(http::verb::get, "/signin/enrol/totp");
  ASSERT_TRUE(enrol);
  ASSERT_EQ(enrol->status, 200u) << enrol->body;
  auto secret = between(enrol->body, "<p class=\"secret\">", "</p>");
  std::erase(secret, ' ');
  ASSERT_FALSE(secret.empty());
  const auto enrol_csrf = between(enrol->body, "name=\"csrf\" value=\"", "\"");

  const auto codes = as_browser(http::verb::post, "/signin/enrol/totp", form({{"csrf", enrol_csrf}, {"code", code_now(secret)}}));
  ASSERT_TRUE(codes);
  ASSERT_EQ(codes->status, 200u) << codes->body;
  EXPECT_NE(codes->body.find("Your recovery codes"), std::string::npos);
  ASSERT_TRUE(jar.has("__Host-lugh_session"));

  // The session opens the API: a person's own routes at mfa; reading needs nothing more, a change
  // its CSRF token. Administering needs phr (the maintainer, 2026-11-16), which a TOTP sign-in is not.
  const auto me = as_browser(http::verb::get, "/api/v1/me");
  ASSERT_TRUE(me);
  ASSERT_EQ(me->status, 200u) << me->body;
  const auto about = boost::json::parse(me->body);
  EXPECT_EQ(about.at("user").at("name"), "root");
  EXPECT_EQ(about.at("user").at("enrolled"), true);
  const auto token = std::string(about.at("session").at("csrf_token").as_string());

  const auto users = as_browser(http::verb::get, "/api/v1/users");
  ASSERT_TRUE(users);
  EXPECT_EQ(users->status, 403u) << users->body;
  EXPECT_EQ(boost::json::parse(users->body).at("error").at("code"), "phr_required");
  const auto json = std::vector<std::pair<std::string, std::string>>{{"Content-Type", "application/json"}};
  auto with_token = json;
  with_token.emplace_back("X-CSRF-Token", token);
  const auto forged = as_browser(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"mail"})", json);
  ASSERT_TRUE(forged);
  EXPECT_EQ(forged->status, 401u) << forged->body;
  const auto made = as_browser(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"mail"})", with_token);
  ASSERT_TRUE(made);
  EXPECT_EQ(made->status, 201u) << made->body;
  const auto refused = as_browser(http::verb::post, "/api/v1/groups", R"({"name":"staff"})", with_token);
  ASSERT_TRUE(refused);
  EXPECT_EQ(refused->status, 403u) << refused->body;

  // The same password signs in again, now to the second factor: the first sign-in's allowance
  // was used once.
  Jar other;
  const auto second_page = send(port, http::verb::get, "/signin");
  ASSERT_TRUE(second_page);
  other.keep(*second_page);
  const auto again = send(port, http::verb::post, "/signin", {{"Cookie", other.header()}, {"Content-Type", "application/x-www-form-urlencoded"}},
                          form({{"csrf", between(second_page->body, "name=\"csrf\" value=\"", "\"")}, {"login", "root"}, {"password", password}}));
  ASSERT_TRUE(again);
  EXPECT_EQ(again->header("Location"), "/signin/factor") << again->body;

  const auto text = serving.stop();
  EXPECT_EQ(text.find(password), std::string::npos) << "root's password is never logged";
  EXPECT_EQ(text.find(secret), std::string::npos) << "nor the TOTP secret";
}

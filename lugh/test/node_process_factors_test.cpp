//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/node_browser.h"

// A person's own factors on the real binary (TODO/2026-11-15-self-factors.md): root, enrolled,
// cannot change a factor until a code reopens the window; then adds a second authenticator,
// removes the first, and signs in again with the second alone. A code for the next step is used
// where one is needed, so no test waits for the clock.

using namespace node_process;
namespace http = boost::beast::http;

namespace {

// The code an authenticator app will show at the next step: inside the accepted window, and after
// any step the last code used.
std::string code_next(const std::string& secret) {
  const auto raw = lugh::encoding::base32_decode(secret);
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  return lugh::authn::totp_code(*raw, lugh::authn::totp_step(static_cast<std::uint64_t>(now)) + 1);
}

std::string error_code(const Reply& reply) { return std::string(boost::json::parse(reply.body).at("error").at("code").as_string()); }

}  // namespace

TEST(NodeProcessFactors, ASecondAuthenticatorReplacesTheFirst) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto password = root_password(node.made.err);
  Serving serving(workspace, node.state, node.credentials);
  ASSERT_TRUE(serving.up()) << serving.log();
  RootBrowser root(serving.port());
  root.sign_in_and_enrol(password);
  if (HasFatalFailure()) return;

  const auto listed = root.browser(http::verb::get, "/api/v1/me/factors");
  ASSERT_TRUE(listed);
  ASSERT_EQ(listed->status, 200u) << listed->body;
  std::string first;
  const auto parsed = boost::json::parse(listed->body);
  for (const auto& factor : parsed.at("factors").as_array())
    if (factor.at("kind") == "totp") first = std::string(factor.at("id").as_string());
  ASSERT_FALSE(first.empty());

  const auto closed = root.api(http::verb::post, "/api/v1/me/factors/totp", "{}");
  ASSERT_TRUE(closed);
  EXPECT_EQ(closed->status, 403u);
  EXPECT_EQ(error_code(*closed), "reauthentication_required");

  const auto opened = root.api(http::verb::post, "/api/v1/me/reauthenticate", R"({"code":")" + code_next(root.secret) + R"("})");
  ASSERT_TRUE(opened);
  ASSERT_EQ(opened->status, 200u) << opened->body;

  const auto made = root.api(http::verb::post, "/api/v1/me/factors/totp", "{}");
  ASSERT_TRUE(made);
  ASSERT_EQ(made->status, 201u) << made->body;
  EXPECT_EQ(made->header("Cache-Control"), "no-store");
  const auto setup = boost::json::parse(made->body);
  const auto second = std::string(setup.at("id").as_string());
  const auto second_secret = std::string(setup.at("secret").as_string());
  const auto confirmed = root.api(http::verb::post, "/api/v1/me/factors/totp/" + second + "/confirm", R"({"code":")" + code_now(second_secret) + R"("})");
  ASSERT_TRUE(confirmed);
  ASSERT_EQ(confirmed->status, 204u) << confirmed->body;
  const auto removed = root.api(http::verb::delete_, "/api/v1/me/factors/" + first, "");
  ASSERT_TRUE(removed);
  ASSERT_EQ(removed->status, 204u) << removed->body;

  // A new browser signs in with the second authenticator alone.
  RootBrowser again(serving.port());
  const auto page = again.browser(http::verb::get, "/signin");
  ASSERT_TRUE(page);
  const auto signed_password = again.browser(http::verb::post, "/signin",
                                             form({{"csrf", between(page->body, "name=\"csrf\" value=\"", "\"")}, {"login", "root"}, {"password", password}}));
  ASSERT_TRUE(signed_password);
  ASSERT_EQ(signed_password->header("Location"), "/signin/factor") << signed_password->body;
  const auto factor = again.browser(http::verb::get, "/signin/factor");
  ASSERT_TRUE(factor);
  const auto csrf = between(factor->body, "name=\"csrf\" value=\"", "\"");
  const auto with_first = again.browser(http::verb::post, "/signin/factor", form({{"csrf", csrf}, {"code", code_next(root.secret)}}));
  ASSERT_TRUE(with_first);
  EXPECT_NE(with_first->status, 303u) << "the removed authenticator signs in no more";
  const auto retry = again.browser(http::verb::get, "/signin/factor");
  ASSERT_TRUE(retry);
  const auto with_second = again.browser(http::verb::post, "/signin/factor",
                                         form({{"csrf", between(retry->body, "name=\"csrf\" value=\"", "\"")}, {"code", code_next(second_secret)}}));
  ASSERT_TRUE(with_second);
  EXPECT_EQ(with_second->status, 303u) << with_second->body;

  const auto text = serving.stop();
  EXPECT_EQ(text.find(second_secret), std::string::npos) << "the new secret is never logged";
}

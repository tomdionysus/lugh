//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/node_process.h"

// /api/v1 through the real binary, over TLS, before P6. A node made with `lugh-node init`
// has root and nothing else: no token, key or setting opens the API. Until sessions and
// OAuth tokens resolve a caller (P6), every route refuses everyone with 401, whatever is
// presented, and an unknown path is still a JSON 404.

using namespace node_process;
namespace http = boost::beast::http;

TEST(NodeProcessApi, NothingOpensItBeforeP6) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto password = root_password(node.made.err);
  ASSERT_FALSE(password.empty()) << node.made.err;

  Serving serving(workspace, node.state, node.credentials);
  ASSERT_TRUE(serving.up()) << "comes up after genesis\n" << serving.log();

  const std::vector<std::optional<std::string>> credentials = {std::nullopt, "Bearer anything", "Bearer " + password, "Basic " + password};
  const std::vector<std::pair<http::verb, std::string>> routes = {
      {http::verb::get, "/api/v1/users"}, {http::verb::post, "/api/v1/users"}, {http::verb::get, "/api/v1/audit"}};
  for (const auto& authorization : credentials) {
    for (const auto& [method, path] : routes) {
      const auto body = method == http::verb::post ? std::optional<std::string>("{}") : std::nullopt;
      const auto answer = request(serving.port(), method, path, authorization, body);
      const auto label = std::string(http::to_string(method)) + " " + path + " with " + authorization.value_or("nothing").substr(0, 6);
      ASSERT_TRUE(answer) << label << ": no answer";
      EXPECT_EQ(answer->status, 401u) << label << ": " << answer->body;
      EXPECT_EQ(answer->json().at("error").at("code"), "unauthorized") << label;
      EXPECT_EQ(answer->www_authenticate, "Bearer realm=\"lugh\"") << label << ": 401 says how";
    }
  }

  const auto unknown = request(serving.port(), http::verb::get, "/api/v1/nothing");
  ASSERT_TRUE(unknown);
  EXPECT_EQ(unknown->status, 404u) << unknown->body;
  EXPECT_EQ(unknown->json().at("error").at("code"), "not_found");

  const auto text = serving.stop();
  EXPECT_NE(text.find("1 users, 1 groups"), std::string::npos) << "the service says who it holds\n" << text;
  EXPECT_EQ(text.find(password), std::string::npos) << "root's password is never logged";
}

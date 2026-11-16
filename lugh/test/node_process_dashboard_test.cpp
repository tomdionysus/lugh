//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/node_process.h"

// The dashboard on the real binary (P7): `static.directory` served for every path the routers do
// not own, a route of the app answered with its page, the reserved paths never; a directory that
// cannot serve stops the node at start; with none, there is no dashboard.

using namespace node_process;
namespace http = boost::beast::http;

namespace {

constexpr const char* kIndex = "<!doctype html><html><head></head><body><div id=\"root\">dashboard</div></body></html>";

}  // namespace

TEST(NodeProcessDashboard, ServedForEveryPathTheRoutersDoNotOwn) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto site = workspace.path("dashboard");
  std::filesystem::create_directories(site / "assets");
  write_file(site / "index.html", kIndex);
  write_file(site / "assets" / "app-1a2b.js", "console.log(1)");
  Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--static-directory", site.string()});
  ASSERT_TRUE(serving.up()) << serving.log();

  for (const auto* path : {"/", "/users", "/groups/g_1"}) {
    const auto page = send(serving.port(), http::verb::get, path);
    ASSERT_TRUE(page) << path;
    EXPECT_EQ(page->status, 200u) << path;
    EXPECT_EQ(page->body, kIndex) << path;
    EXPECT_NE(page->header("Content-Security-Policy").find("default-src 'self'"), std::string::npos) << path;
  }
  const auto script = send(serving.port(), http::verb::get, "/assets/app-1a2b.js");
  ASSERT_TRUE(script);
  EXPECT_EQ(script->body, "console.log(1)");
  EXPECT_EQ(script->header("Cache-Control"), "public, max-age=31536000, immutable");

  // The reserved paths are the routers': JSON, never the page.
  for (const auto* reserved : {"/api/v1/nothing", "/oauth2/nothing", "/.well-known/nothing"}) {
    const auto answer = send(serving.port(), http::verb::get, reserved);
    ASSERT_TRUE(answer) << reserved;
    EXPECT_EQ(answer->status, 404u) << reserved;
    EXPECT_EQ(answer->body.find("dashboard"), std::string::npos) << reserved;
  }
  const auto signin = send(serving.port(), http::verb::get, "/signin");
  ASSERT_TRUE(signin);
  EXPECT_EQ(signin->status, 200u);
  EXPECT_EQ(signin->body.find("dashboard"), std::string::npos) << "the sign-in is its own page";

  EXPECT_NE(serving.stop().find("The dashboard: 2 files"), std::string::npos);
}

TEST(NodeProcessDashboard, ADirectoryThatCannotServeStopsTheStart) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto empty = workspace.path("empty");
  std::filesystem::create_directories(empty);
  write_file(empty / "app.js", "1");
  Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--static-directory", empty.string()});
  EXPECT_FALSE(serving.up());
  EXPECT_NE(serving.stop().find("has no index.html"), std::string::npos);
}

TEST(NodeProcessDashboard, WithoutOneThereIsNone) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  Serving serving(workspace, node.state, node.credentials);
  ASSERT_TRUE(serving.up()) << serving.log();
  const auto root = send(serving.port(), http::verb::get, "/");
  ASSERT_TRUE(root);
  EXPECT_EQ(root->status, 404u);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The dashboard's files (P7; docs/architecture.md, "Frontend"): read once from static.directory,
// symbolic links and dot-files left out; each file with its type, ETag and caching; a route of
// the SPA answered with index.html and a missing file with a 404; every page under a policy that
// allows this origin and its own inline scripts, nothing else.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/json.hpp>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/http/static_site.h"
#include "lugh/test/fixtures/route_call.h"
#include "lugh/test/fixtures/temp_directory.h"

namespace http = lugh::http;
using http::StaticSite;

namespace {

constexpr const char* kIndex = "<!doctype html><html><head><script>window.__context={}</script></head><body><div id=\"root\"></div></body></html>";

StaticSite site() {
  return StaticSite({{"index.html", kIndex}, {"assets/app-1a2b3c.js", "console.log(1)"}, {"assets/app-1a2b3c.css", "body{}"}, {"favicon.ico", "ico"}});
}

RouteCall get(const StaticSite& served, const std::string& target, std::vector<std::pair<std::string, std::string>> headers = {},
              http::verb method = http::verb::get) {
  boost::asio::io_context io;
  return call(io, served.middleware(), method, target, "192.0.2.1", "", headers);
}

std::string header(const RouteCall& result, const std::string& name) { return std::string(result.response->base()[name]); }

}  // namespace

TEST(StaticSite, EachFileWithItsTypeAndCaching) {
  const auto served = site();
  const auto script = get(served, "/assets/app-1a2b3c.js");
  ASSERT_TRUE(script.answered);
  EXPECT_EQ(script.response->result(), http::status::ok);
  EXPECT_EQ(script.response->body(), "console.log(1)");
  EXPECT_EQ(header(script, "Content-Type"), "text/javascript; charset=utf-8");
  EXPECT_EQ(header(script, "Cache-Control"), "public, max-age=31536000, immutable") << "Vite fingerprints its assets";
  EXPECT_EQ(header(script, "X-Content-Type-Options"), "nosniff");
  EXPECT_EQ(header(get(served, "/assets/app-1a2b3c.css"), "Content-Type"), "text/css; charset=utf-8");

  const auto index = get(served, "/");
  EXPECT_EQ(index.response->body(), kIndex);
  EXPECT_EQ(header(index, "Content-Type"), "text/html; charset=utf-8");
  EXPECT_EQ(header(index, "Cache-Control"), "no-cache") << "the page names the current assets, so it is checked each time";

  // Its ETag, sent back, is a 304 with no body.
  const auto again = get(served, "/", {{"If-None-Match", header(index, "ETag")}});
  EXPECT_EQ(again.response->result(), http::status::not_modified);
  EXPECT_TRUE(again.response->body().empty());

  const auto head = get(served, "/favicon.ico", {}, http::verb::head);
  EXPECT_EQ(head.response->result(), http::status::ok);
  EXPECT_TRUE(head.response->body().empty());
}

TEST(StaticSite, ARouteOfTheAppIsItsPageAndAMissingFileIsNot) {
  const auto served = site();
  for (const auto* route : {"/users", "/users/u_123", "/groups/g_1/members?x=1"}) {
    const auto page = get(served, route);
    EXPECT_EQ(page.response->result(), http::status::ok) << route;
    EXPECT_EQ(page.response->body(), kIndex) << route;
  }
  for (const auto* missing : {"/assets/gone-0000.js", "/robots.txt", "/../secret.txt", "/assets/../../etc/passwd.txt"}) {
    const auto answer = get(served, missing);
    EXPECT_EQ(answer.response->result(), http::status::not_found) << missing;
    EXPECT_EQ(boost::json::parse(answer.response->body()).at("error").at("code"), "not_found") << missing;
  }
  const auto posted = get(served, "/users", {}, http::verb::post);
  EXPECT_EQ(posted.response->result(), http::status::method_not_allowed);
  EXPECT_EQ(header(posted, "Allow"), "GET, HEAD");
}

// The page allows this origin only, and its inline script by hash, so an injected one does not run.
TEST(StaticSite, APageAllowsOnlyItsOwnScripts) {
  const auto page = get(site(), "/");
  const auto policy = header(page, "Content-Security-Policy");
  const std::string inline_script = "window.__context={}";
  const auto hash = lugh::encoding::base64(
      dannan::identity::sha256(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(inline_script.data()), inline_script.size())).bytes);
  EXPECT_NE(policy.find("default-src 'self'"), std::string::npos) << policy;
  EXPECT_NE(policy.find("script-src 'self' 'sha256-" + hash + "'"), std::string::npos) << policy;
  EXPECT_NE(policy.find("frame-ancestors 'none'"), std::string::npos) << policy;
  EXPECT_EQ(policy.find("unsafe"), std::string::npos) << policy;
  EXPECT_EQ(header(page, "X-Frame-Options"), "DENY");
  EXPECT_TRUE(header(get(site(), "/assets/app-1a2b3c.js"), "Content-Security-Policy").empty()) << "only a page carries one";
  // A script with a source is allowed by origin, not by hash.
  EXPECT_EQ(StaticSite::page_policy("<script type=\"module\" src=\"/assets/a.js\"></script>").find("sha256"), std::string::npos);
}

TEST(StaticSite, ReadingLeavesOutLinksAndDotFiles) {
  TempDirectory dir;
  const auto root = dir.path() / "client";
  dir.write("client/index.html", kIndex);
  dir.write("client/assets/app.js", "1");
  dir.write("client/.env", "SECRET=1");
  dir.write("client/.git/config", "x");
  dir.write("outside.txt", "not the dashboard's");
  std::filesystem::create_symlink(dir.path() / "outside.txt", root / "linked.txt");
  std::filesystem::create_directory_symlink(dir.path(), root / "up");

  const auto files = StaticSite::read(root);
  EXPECT_EQ(files.size(), 2u);
  EXPECT_TRUE(files.count("index.html"));
  EXPECT_TRUE(files.count("assets/app.js"));
  for (const auto& [path, body] : files) EXPECT_EQ(body.find("not the dashboard's"), std::string::npos) << path;
}

TEST(StaticSite, ADirectoryThatCannotServeIsRefusedAtTheStart) {
  TempDirectory dir;
  EXPECT_THROW(StaticSite::read(dir.path() / "missing"), std::runtime_error);
  dir.write("empty/app.js", "1");
  EXPECT_THROW(StaticSite::read(dir.path() / "empty"), std::runtime_error) << "no index.html";
  dir.write("big/index.html", std::string(200, 'x'));
  dir.write("big/a.js", std::string(200, 'x'));
  EXPECT_THROW(StaticSite::read(dir.path() / "big", StaticSite::Limits{10, 300}), std::runtime_error) << "past the byte limit";
  EXPECT_THROW(StaticSite::read(dir.path() / "big", StaticSite::Limits{1, 1000}), std::runtime_error) << "past the file limit";
  EXPECT_NO_THROW(StaticSite::read(dir.path() / "big", StaticSite::Limits{10, 1000}));
  EXPECT_THROW(StaticSite({{"app.js", "1"}}), std::invalid_argument);
}

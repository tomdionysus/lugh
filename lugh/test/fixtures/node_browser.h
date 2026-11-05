//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "dannan/encoding/percent.h"
#include "lugh/authn/totp.h"
#include "lugh/core/encoding.h"
#include "lugh/test/fixtures/node_process.h"

// What a browser and an authenticator app do, for the process tests.
namespace node_process {

// A browser's cookies.
class Jar {
 public:
  void keep(const Reply& reply) {
    for (const auto& value : reply.all("Set-Cookie")) {
      const auto equals = value.find('=');
      const auto end = value.find(';');
      const auto name = value.substr(0, equals);
      if (value.find("Max-Age=0") != std::string::npos) {
        _cookies.erase(name);
      } else {
        _cookies[name] = value.substr(equals + 1, end - equals - 1);
      }
    }
  }
  std::string header() const {
    std::string out;
    for (const auto& [name, value] : _cookies) out += (out.empty() ? "" : "; ") + name + "=" + value;
    return out;
  }
  bool has(const std::string& name) const { return _cookies.count(name) > 0; }

 private:
  std::map<std::string, std::string> _cookies;
};

inline std::string between(const std::string& text, const std::string& before, const std::string& after) {
  const auto start = text.find(before);
  if (start == std::string::npos) return {};
  const auto from = start + before.size();
  return text.substr(from, text.find(after, from) - from);
}

inline std::string form(const std::map<std::string, std::string>& fields) {
  std::string out;
  for (const auto& [name, value] : fields) {
    out += (out.empty() ? "" : "&") + name + "=" + dannan::encoding::percent_encode(value, dannan::encoding::PercentSet::form());
  }
  return out;
}

// The code an authenticator app shows now for a base32 secret.
inline std::string code_now(const std::string& secret) {
  const auto raw = lugh::encoding::base32_decode(secret);
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  return lugh::authn::totp_code(*raw, lugh::authn::totp_step(static_cast<std::uint64_t>(now)));
}

// Root, signed in and enrolled through the pages, as a browser and as the dashboard.
class RootBrowser {
 public:
  explicit RootBrowser(std::uint16_t port_now = 0) : port(port_now) {}

  // Cookies kept and sent, bodies typed.
  std::optional<Reply> browser(boost::beast::http::verb method, const std::string& target, const std::string& body = "",
                               std::vector<std::pair<std::string, std::string>> headers = {}) {
    if (!jar.header().empty()) headers.emplace_back("Cookie", jar.header());
    const bool typed = std::any_of(headers.begin(), headers.end(), [](const auto& one) { return one.first == "Content-Type"; });
    if (!body.empty() && !typed) headers.emplace_back("Content-Type", "application/x-www-form-urlencoded");
    auto reply = send(port, method, target, headers, body);
    if (reply) jar.keep(*reply);
    return reply;
  }

  // JSON, with the session's CSRF token.
  std::optional<Reply> api(boost::beast::http::verb method, const std::string& target, const std::string& body) {
    return browser(method, target, body, {{"Content-Type", "application/json"}, {"X-CSRF-Token", csrf_token}});
  }

  void sign_in_and_enrol(const std::string& password) {
    namespace http = boost::beast::http;
    const auto page = browser(http::verb::get, "/signin");
    ASSERT_TRUE(page);
    const auto signed_password =
        browser(http::verb::post, "/signin", form({{"csrf", between(page->body, "name=\"csrf\" value=\"", "\"")}, {"login", "root"}, {"password", password}}));
    ASSERT_TRUE(signed_password);
    ASSERT_EQ(signed_password->header("Location"), "/signin/enrol/totp") << signed_password->body;
    const auto enrol = browser(http::verb::get, "/signin/enrol/totp");
    ASSERT_TRUE(enrol);
    secret = between(enrol->body, "<p class=\"secret\">", "</p>");
    std::erase(secret, ' ');
    const auto codes =
        browser(http::verb::post, "/signin/enrol/totp", form({{"csrf", between(enrol->body, "name=\"csrf\" value=\"", "\"")}, {"code", code_now(secret)}}));
    ASSERT_TRUE(codes);
    ASSERT_EQ(codes->status, 200u) << codes->body;
    const auto me = browser(http::verb::get, "/api/v1/me");
    ASSERT_TRUE(me);
    ASSERT_EQ(me->status, 200u) << me->body;
    const auto about = boost::json::parse(me->body);
    root_id = std::string(about.at("user").at("id").as_string());
    csrf_token = std::string(about.at("session").at("csrf_token").as_string());
  }

  std::uint16_t port;
  Jar jar;
  std::string secret;
  std::string root_id;
  std::string csrf_token;
};

}  // namespace node_process

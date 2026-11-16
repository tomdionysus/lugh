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
#include "lugh/test/fixtures/soft_authenticator.h"

// What a browser and an authenticator app do, for the process tests.
namespace node_process {

// `--config` for a node whose oauth.issuer is `issuer`, written into the workspace: WebAuthn is
// offered only with one.
inline std::vector<std::string> issuer_arguments(const Workspace& workspace, const std::string& issuer = "https://id.example.test") {
  const auto path = workspace.path("issuer.yaml");
  write_file(path, "oauth: { issuer: " + issuer + " }\n");
  return {"--config", path.string()};
}

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

  // Root's first sign-in enrolling a passkey instead (the maintainer, 2026-11-16: root is offered both), so the
  // session is at phr and may administer. The node must have `issuer` as its oauth.issuer: its
  // host is the RP ID and its origin the one the ceremony carries.
  void sign_in_and_enrol_passkey(const std::string& password, const std::string& issuer = kTestIssuer) {
    namespace http = boost::beast::http;
    const auto authority = issuer.substr(issuer.find("://") + 3);
    key.origin = "https://" + authority;
    key.rp_id = authority.substr(0, authority.find(':'));
    const auto page = browser(http::verb::get, "/signin");
    ASSERT_TRUE(page);
    const auto signed_password =
        browser(http::verb::post, "/signin", form({{"csrf", between(page->body, "name=\"csrf\" value=\"", "\"")}, {"login", "root"}, {"password", password}}));
    ASSERT_TRUE(signed_password);
    ASSERT_EQ(signed_password->header("Location"), "/signin/enrol/totp") << signed_password->body;
    const auto enrol = browser(http::verb::get, "/signin/enrol/totp");
    ASSERT_TRUE(enrol);
    ASSERT_NE(enrol->body.find("data-webauthn=\"enrol\""), std::string::npos) << "root is offered a passkey";
    const auto csrf = between(enrol->body, "name=\"csrf\" value=\"", "\"");
    const auto asked =
        browser(http::verb::post, "/signin/webauthn/options", R"({"purpose":"enrol"})", {{"Content-Type", "application/json"}, {"X-CSRF-Token", csrf}});
    ASSERT_TRUE(asked);
    ASSERT_EQ(asked->status, 200u) << asked->body;
    const auto challenge = std::string(boost::json::parse(asked->body).at("challenge").as_string());
    const auto raw = lugh::encoding::base64url_decode(challenge);
    ASSERT_TRUE(raw);
    const auto created = key.create(std::string(raw->begin(), raw->end()));
    const auto codes = browser(http::verb::post, "/signin/webauthn",
                               form({{"csrf", csrf},
                                     {"purpose", "enrol"},
                                     {"challenge", challenge},
                                     {"id", lugh::encoding::base64url(key.credential_id())},
                                     {"client_data", lugh::encoding::base64url(created.client_data_json)},
                                     {"attestation_object", lugh::encoding::base64url(created.attestation_object)},
                                     {"name", "root's key"}}));
    ASSERT_TRUE(codes);
    ASSERT_EQ(codes->status, 200u) << codes->body;
    const auto me = browser(http::verb::get, "/api/v1/me");
    ASSERT_TRUE(me);
    ASSERT_EQ(me->status, 200u) << me->body;
    const auto about = boost::json::parse(me->body);
    ASSERT_EQ(about.at("session").at("acr"), "urn:lugh:acr:phr");
    root_id = std::string(about.at("user").at("id").as_string());
    csrf_token = std::string(about.at("session").at("csrf_token").as_string());
  }

  // An issuer for a node whose tests do not reach it by its URL.
  static constexpr const char* kTestIssuer = "https://id.example.test";

  std::uint16_t port;
  Jar jar;
  soft_authenticator::Authenticator key;
  std::string secret;
  std::string root_id;
  std::string csrf_token;
};

}  // namespace node_process

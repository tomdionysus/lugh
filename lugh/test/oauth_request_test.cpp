//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/oauth/request.h"

using namespace lugh::oauth;
using lugh::apps::App;
using Strings = std::vector<std::string>;

namespace {

App web() {
  App app;
  app.client_id = "app_web";
  app.name = "admin";
  app.kind = lugh::apps::Kind::web;
  app.grants = lugh::apps::kAuthorizationCode;
  app.redirect_uris = {"https://admin.example.com/cb"};
  app.scopes = {"openid", "profile", "lugh:directory.read"};
  return app;
}

// RFC 7636 appendix B.
constexpr const char* kVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
constexpr const char* kChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

Parameters good() {
  return {{"response_type", "code"},
          {"client_id", "app_web"},
          {"redirect_uri", "https://admin.example.com/cb"},
          {"state", "s1"},
          {"scope", "openid profile"},
          {"nonce", "n1"},
          {"code_challenge", kChallenge},
          {"code_challenge_method", "S256"}};
}

RequestError error_of(const App& app, const Parameters& parameters) {
  const auto checked = check_request(app, parameters);
  EXPECT_TRUE(std::holds_alternative<RequestError>(checked));
  return std::holds_alternative<RequestError>(checked) ? std::get<RequestError>(checked) : RequestError{};
}

}  // namespace

TEST(Request, PkceIsRfc7636AppendixB) {
  EXPECT_TRUE(pkce_ok(kVerifier, kChallenge));
  EXPECT_FALSE(pkce_ok(std::string(kVerifier) + "x", kChallenge));
  EXPECT_FALSE(pkce_ok("short", kChallenge));
  EXPECT_FALSE(pkce_ok(std::string(129, 'a'), kChallenge));
  EXPECT_FALSE(pkce_ok(std::string(43, '+'), kChallenge));
}

TEST(Request, AGoodOne) {
  const auto checked = check_request(web(), good());
  ASSERT_TRUE(std::holds_alternative<AuthorizationRequest>(checked));
  const auto& request = std::get<AuthorizationRequest>(checked);
  EXPECT_EQ(request.scopes, (Strings{"openid", "profile"}));
  EXPECT_EQ(request.nonce, "n1");
  EXPECT_EQ(request.code_challenge, kChallenge);
}

// Until the redirect URI is known to be the client's, nothing is sent to it.
TEST(Request, AnUntrustedRedirectIsNeverUsed) {
  auto parameters = good();
  parameters["redirect_uri"] = "https://admin.example.com/cb/other";
  EXPECT_FALSE(error_of(web(), parameters).redirect);
  parameters.erase("redirect_uri");
  EXPECT_FALSE(error_of(web(), parameters).redirect);
  auto disabled = web();
  disabled.state = lugh::apps::State::disabled;
  EXPECT_FALSE(error_of(disabled, good()).redirect);
}

TEST(Request, RefusalsGoBackToTheClient) {
  const auto with = [](const std::string& name, const std::string& value) {
    auto parameters = good();
    if (value.empty()) {
      parameters.erase(name);
    } else {
      parameters[name] = value;
    }
    return parameters;
  };
  EXPECT_EQ(error_of(web(), with("response_type", "token")).error, "unsupported_response_type");
  EXPECT_EQ(error_of(web(), with("code_challenge_method", "plain")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("code_challenge", "")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("state", "")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("nonce", "")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("scope", "openid email")).error, "invalid_scope");
  EXPECT_EQ(error_of(web(), with("prompt", "none login")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("prompt", "select_account")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("max_age", "soon")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("response_mode", "fragment")).error, "invalid_request");
  EXPECT_EQ(error_of(web(), with("request", "eyJ...")).error, "request_not_supported");
  auto service = web();
  service.grants = lugh::apps::kClientCredentials;
  EXPECT_EQ(error_of(service, good()).error, "unauthorized_client");
}

TEST(Request, PromptMaxAgeAndAcr) {
  auto parameters = good();
  parameters["prompt"] = "login consent";
  parameters["max_age"] = "300";
  parameters["acr_values"] = "urn:other urn:lugh:acr:mfa urn:lugh:acr:pwd";
  const auto request = std::get<AuthorizationRequest>(check_request(web(), parameters));
  EXPECT_EQ(request.prompt, "login consent");
  EXPECT_EQ(request.max_age, 300u);
  EXPECT_EQ(request.acr, lugh::authn::Assurance::mfa);
}

// RFC 8252 section 7.3: a native app's loopback redirect matches whatever port it picked.
TEST(Request, LoopbackPortsForNativeAppsOnly) {
  auto native = web();
  native.kind = lugh::apps::Kind::native;
  native.redirect_uris = {"http://127.0.0.1/cb", "http://[::1]/cb"};
  EXPECT_TRUE(redirect_registered(native, "http://127.0.0.1:51004/cb"));
  EXPECT_TRUE(redirect_registered(native, "http://[::1]:8080/cb"));
  EXPECT_TRUE(redirect_registered(native, "http://127.0.0.1/cb"));
  EXPECT_FALSE(redirect_registered(native, "http://127.0.0.1:51004/other"));
  EXPECT_FALSE(redirect_registered(native, "http://127.0.0.1:x/cb"));
  EXPECT_FALSE(redirect_registered(web(), "https://admin.example.com:443/cb"));
}

// A token carries what was asked, of what the subject holds, for its audiences.
TEST(Request, GrantedScopes) {
  const Strings asked{"openid", "profile", "lugh:directory.read", "lugh:audit.read", "toms:dns", "lir:sub:a/#"};
  const Strings held{"lugh:directory.read", "toms:dns", "lir:sub:a/#"};
  EXPECT_EQ(granted_scopes(asked, held, {"lugh"}), (Strings{"lugh:directory.read", "openid", "profile"}));
  EXPECT_EQ(granted_scopes(asked, held, {"toms", "lir"}), (Strings{"lir:sub:a/#", "openid", "profile", "toms:dns"}));
  EXPECT_EQ(granted_scopes(asked, held, {}), (Strings{"openid", "profile"}));
}

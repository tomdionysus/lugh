//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/scopes/scope.h"
#include "lugh/test/fixtures/signin_rig.h"
#include "lugh/tokens/jose.h"

using lugh::http::verb;
using Strings = std::vector<std::string>;

namespace {

constexpr const char* kPassword = "correct horse battery";
constexpr const char* kRedirect = "https://client.example.com/cb";
// RFC 7636 appendix B.
constexpr const char* kVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
constexpr const char* kChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

std::string query_value(const std::string& uri, const std::string& name) {
  const auto question = uri.find('?');
  if (question == std::string::npos) return {};
  std::size_t at = question + 1;
  while (at < uri.size()) {
    const auto end = std::min(uri.find('&', at), uri.size());
    const auto part = uri.substr(at, end - at);
    const auto equals = part.find('=');
    if (part.substr(0, equals) == name) return dannan::encoding::percent_decode(part.substr(equals + 1), dannan::encoding::Decoding::form);
    at = end + 1;
  }
  return {};
}

std::string basic(const std::string& client_id, const std::string& secret) {
  const auto text = client_id + ":" + secret;
  auto encoded = lugh::encoding::base64url(lugh::byte_span(text));
  for (auto& c : encoded) c = c == '-' ? '+' : (c == '_' ? '/' : c);
  while (encoded.size() % 4) encoded.push_back('=');
  return "Basic " + encoded;
}

boost::json::object claims_of(const std::string& token) { return lugh::tokens::jws_parse(token)->claims; }

class OAuthFlowTest : public ::testing::Test {
 protected:
  void SetUp() override {
    alice = rig.enrolled("alice");
    staff = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
              rig.directory->create_group(rig.admin, "staff", "", kTestDeadline, executor, done);
            }).value;
    ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                  rig.directory->add_member(rig.admin, staff.id, alice.id, kTestDeadline, executor, done);
                }).ok());
    ASSERT_TRUE(wait_for<lugh::Outcome<lugh::scopes::Granted>>([&](lugh::Executor executor, auto done) {
                  rig.grants->group_set(rig.admin, staff.id, {"lugh:directory.read"}, std::nullopt, kTestDeadline, executor, done);
                }).ok());
  }

  // A web application allowed to staff; first party unless said otherwise.
  std::pair<lugh::apps::App, std::string> register_web(bool first_party = true) {
    lugh::apps::App draft;
    draft.name = "Client";
    draft.kind = lugh::apps::Kind::web;
    draft.auth = lugh::apps::ClientAuth::client_secret_basic;
    draft.grants = lugh::apps::kAuthorizationCode;
    draft.redirect_uris = {kRedirect};
    draft.scopes = {"openid", "profile", "email", "groups", "lugh:directory.read"};
    draft.audiences = {"lugh"};
    draft.first_party = first_party;
    auto made = wait_for<lugh::Outcome<lugh::apps::Apps::Made>>(
        [&](lugh::Executor executor, auto done) { rig.apps->create(rig.admin, draft, kTestDeadline, executor, done); });
    EXPECT_TRUE(made.ok()) << made.message;
    const auto id = made.value.app.client_id;
    EXPECT_TRUE(wait_for<lugh::Outcome<lugh::apps::App>>([&](lugh::Executor executor, auto done) {
                  rig.apps->access_set(rig.admin, id, staff.id, true, kTestDeadline, executor, done);
                }).ok());
    return {made.value.app, std::string(lugh::secret_text(*made.value.secret))};
  }

  std::string authorize_target(const std::string& client_id, const std::string& extra = "") {
    return "/oauth2/authorize?response_type=code&client_id=" + client_id + "&redirect_uri=" + dannan::encoding::percent_encode(kRedirect) +
           "&scope=openid%20profile%20groups%20lugh%3Adirectory.read&state=st8&nonce=n0nce&code_challenge=" + kChallenge + "&code_challenge_method=S256" +
           extra;
  }

  // Through the sign-in the authorisation request sends the browser to; the final redirect.
  std::string sign_in_through(const std::string& signin_location) {
    EXPECT_EQ(signin_location.rfind("/signin?continue=", 0), 0u) << signin_location;
    const auto form = rig.get(signin_location);
    const auto resume = form.between("name=\"continue\" value=\"", "\"");
    EXPECT_FALSE(resume.empty());
    const auto password = rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}, {"continue", resume}});
    EXPECT_EQ(password.location(), "/signin/factor");
    const auto factor = rig.get("/signin/factor");
    const auto done = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
    EXPECT_EQ(done.location().rfind("/oauth2/authorize/resume?id=", 0), 0u) << done.location();
    return rig.get(done.location()).location();
  }

  SigninRig::Page redeem(const std::string& client_id, const std::string& secret, const std::string& code, const std::string& verifier = kVerifier) {
    return rig.request(verb::post, "/oauth2/token",
                       {{"grant_type", "authorization_code"}, {"code", code}, {"redirect_uri", kRedirect}, {"code_verifier", verifier}},
                       {{"Authorization", basic(client_id, secret)}});
  }

  SigninRig rig;
  lugh::directory::User alice;
  lugh::directory::Group staff;
};

}  // namespace

// The whole of it: no session, so to sign-in; back with a code; the code for tokens.
TEST_F(OAuthFlowTest, TheCodeFlowWithPkce) {
  const auto [app, secret] = register_web();
  const auto first = rig.get(authorize_target(app.client_id));
  ASSERT_EQ(first.status, 303u) << first.body;
  const auto back = sign_in_through(first.location());
  ASSERT_EQ(back.rfind(kRedirect, 0), 0u) << back;
  EXPECT_EQ(query_value(back, "state"), "st8");
  EXPECT_EQ(query_value(back, "iss"), SigninRig::kIssuer);
  const auto code = query_value(back, "code");
  ASSERT_FALSE(code.empty());

  const auto tokens = redeem(app.client_id, secret, code);
  ASSERT_EQ(tokens.status, 200u) << tokens.body;
  EXPECT_EQ(tokens.header("Cache-Control"), "no-store");
  const auto body = boost::json::parse(tokens.body);
  EXPECT_EQ(body.at("token_type"), "Bearer");
  EXPECT_EQ(body.at("expires_in"), 300);
  EXPECT_EQ(body.at("scope"), "groups lugh:directory.read openid profile");

  const auto access = std::string(body.at("access_token").as_string());
  const auto access_claims = claims_of(access);
  EXPECT_EQ(lugh::tokens::jws_parse(access)->typ, "at+jwt");
  EXPECT_EQ(access_claims.at("sub"), boost::json::value(alice.id));
  EXPECT_EQ(access_claims.at("client_id"), boost::json::value(app.client_id));
  EXPECT_EQ(access_claims.at("aud"), (boost::json::array{"lugh"}));
  EXPECT_EQ(access_claims.at("acr"), "urn:lugh:acr:mfa");
  EXPECT_EQ(access_claims.at("amr"), (boost::json::array{"pwd", "otp"}));

  const auto id = claims_of(std::string(body.at("id_token").as_string()));
  EXPECT_EQ(id.at("iss"), boost::json::value(SigninRig::kIssuer));
  EXPECT_EQ(id.at("aud"), boost::json::value(app.client_id));
  EXPECT_EQ(id.at("nonce"), "n0nce");
  EXPECT_EQ(id.at("preferred_username"), "alice");
  EXPECT_EQ(id.at("groups"), (boost::json::array{"staff"}));
  // OIDC Core 3.1.3.6: the left half of SHA-256 of the access token.
  const auto hash = dannan::identity::sha256(lugh::byte_span(access));
  EXPECT_EQ(id.at("at_hash"), boost::json::value(lugh::encoding::base64url(std::span<const unsigned char>(hash.bytes).first(16))));

  // The token opens the API with what alice holds, and userinfo with what she let it see.
  EXPECT_EQ(rig.request(verb::get, "/api/v1/users", {}, {{"Authorization", "Bearer " + access}}).status, 200u);
  EXPECT_EQ(rig.request(verb::post, "/api/v1/users", {}, {{"Authorization", "Bearer " + access}}).status, 403u);
  const auto info = rig.request(verb::get, "/oauth2/userinfo", {}, {{"Authorization", "Bearer " + access}});
  ASSERT_EQ(info.status, 200u) << info.body;
  EXPECT_EQ(boost::json::parse(info.body).at("sub"), boost::json::value(alice.id));

  // A code works once.
  EXPECT_EQ(boost::json::parse(redeem(app.client_id, secret, code).body).at("error"), "invalid_grant");
}

TEST_F(OAuthFlowTest, ACodeIsBoundToItsClientRedirectAndVerifier) {
  const auto [app, secret] = register_web();
  const auto [other, other_secret] = register_web();
  rig.get(authorize_target(app.client_id));
  const auto first = rig.get(authorize_target(app.client_id));
  const auto code = [&] {
    const auto back = rig.get(authorize_target(app.client_id));
    return query_value(back.location(), "code");
  };
  // Signed in once, the next request goes straight back with a code.
  sign_in_through(first.location());

  EXPECT_EQ(boost::json::parse(redeem(app.client_id, secret, code(), std::string(43, 'a')).body).at("error"), "invalid_grant");
  EXPECT_EQ(boost::json::parse(redeem(other.client_id, other_secret, code()).body).at("error"), "invalid_grant");
  const auto wrong_secret = redeem(app.client_id, "not it", code());
  EXPECT_EQ(wrong_secret.status, 401u);
  EXPECT_EQ(boost::json::parse(wrong_secret.body).at("error"), "invalid_client");
  const auto other_uri =
      rig.request(verb::post, "/oauth2/token",
                  {{"grant_type", "authorization_code"}, {"code", code()}, {"redirect_uri", "https://client.example.com/x"}, {"code_verifier", kVerifier}},
                  {{"Authorization", basic(app.client_id, secret)}});
  EXPECT_EQ(boost::json::parse(other_uri.body).at("error"), "invalid_grant");
  EXPECT_EQ(redeem(app.client_id, secret, code()).status, 200u);
}

TEST_F(OAuthFlowTest, RefusalsAtTheAuthorizationEndpoint) {
  const auto [app, secret] = register_web();
  // An unknown client or redirect: a page on Lugh, never a redirect.
  EXPECT_EQ(rig.get("/oauth2/authorize?client_id=app_nobody").status, 400u);
  const auto bad_uri = rig.get("/oauth2/authorize?response_type=code&client_id=" + app.client_id + "&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcb");
  EXPECT_EQ(bad_uri.status, 400u);
  EXPECT_TRUE(bad_uri.location().empty());
  // Anything else goes back with state and iss.
  const auto no_pkce = rig.get(authorize_target(app.client_id, "&code_challenge_method=plain"));
  EXPECT_EQ(query_value(no_pkce.location(), "error"), "invalid_request");
  EXPECT_EQ(query_value(no_pkce.location(), "state"), "st8");
  // prompt=none without a session.
  const auto silent = rig.get(authorize_target(app.client_id, "&prompt=none"));
  EXPECT_EQ(query_value(silent.location(), "error"), "login_required");
  // Asking for phr before WebAuthn exists.
  const auto phr = rig.get(authorize_target(app.client_id, "&acr_values=urn%3Alugh%3Aacr%3Aphr"));
  EXPECT_EQ(query_value(phr.location(), "error"), "unmet_authentication_requirements");
}

TEST_F(OAuthFlowTest, OnlyTheAppsGroupsMayUseIt) {
  const auto [app, secret] = register_web();
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::apps::App>>([&](lugh::Executor executor, auto done) {
                rig.apps->access_set(rig.admin, app.client_id, staff.id, false, kTestDeadline, executor, done);
              }).ok());
  const auto back = sign_in_through(rig.get(authorize_target(app.client_id)).location());
  EXPECT_EQ(query_value(back, "error"), "access_denied");
}

// A third-party application asks once; a first-party one never.
TEST_F(OAuthFlowTest, ConsentForThirdParties) {
  const auto [app, secret] = register_web(false);
  const auto at_consent = sign_in_through(rig.get(authorize_target(app.client_id)).location());
  ASSERT_EQ(at_consent.rfind("/oauth2/consent?id=", 0), 0u) << at_consent;
  const auto page = rig.get(at_consent);
  ASSERT_EQ(page.status, 200u) << page.body;
  EXPECT_TRUE(page.says("Client"));
  EXPECT_TRUE(page.says("See which groups you are in"));
  const auto id = page.between("name=\"id\" value=\"", "\"");

  EXPECT_EQ(rig.post("/oauth2/consent", {{"csrf", "forged"}, {"id", id}, {"decision", "allow"}}).status, 400u);
  const auto allowed = rig.post("/oauth2/consent", {{"csrf", page.csrf()}, {"id", id}, {"decision", "allow"}});
  EXPECT_FALSE(query_value(allowed.location(), "code").empty()) << allowed.location();
  EXPECT_TRUE(rig.audited("consent.grant"));
  // Asked again for the same: straight back.
  EXPECT_FALSE(query_value(rig.get(authorize_target(app.client_id)).location(), "code").empty());
  // prompt=consent asks anyway; denying sends access_denied.
  const auto again = rig.get(rig.get(authorize_target(app.client_id, "&prompt=consent")).location());
  const auto denied = rig.post("/oauth2/consent", {{"csrf", again.csrf()}, {"id", again.between("name=\"id\" value=\"", "\"")}, {"decision", "deny"}});
  EXPECT_EQ(query_value(denied.location(), "error"), "access_denied");
}

// A client acting for itself: client credentials, its own scopes, a service caller at the API.
TEST_F(OAuthFlowTest, ClientCredentials) {
  lugh::apps::App draft;
  draft.name = "hub";
  draft.kind = lugh::apps::Kind::service;
  draft.auth = lugh::apps::ClientAuth::client_secret_basic;
  draft.grants = lugh::apps::kClientCredentials;
  draft.client_scopes = {"lugh:directory.read", "lugh:audit.read"};
  draft.audiences = {"lugh"};
  const auto made = wait_for<lugh::Outcome<lugh::apps::Apps::Made>>(
      [&](lugh::Executor executor, auto done) { rig.apps->create(rig.admin, draft, kTestDeadline, executor, done); });
  ASSERT_TRUE(made.ok());
  const auto id = made.value.app.client_id;
  const auto secret = std::string(lugh::secret_text(*made.value.secret));

  const auto token = rig.request(verb::post, "/oauth2/token", {{"grant_type", "client_credentials"}, {"scope", "lugh:directory.read"}},
                                 {{"Authorization", basic(id, secret)}});
  ASSERT_EQ(token.status, 200u) << token.body;
  const auto access = std::string(boost::json::parse(token.body).at("access_token").as_string());
  EXPECT_EQ(claims_of(access).at("sub"), boost::json::value(id));
  EXPECT_FALSE(boost::json::parse(token.body).as_object().contains("id_token"));
  EXPECT_EQ(rig.request(verb::get, "/api/v1/users", {}, {{"Authorization", "Bearer " + access}}).status, 200u);
  // It holds directory.read, not directory.write.
  EXPECT_EQ(rig.request(verb::post, "/api/v1/users", {}, {{"Authorization", "Bearer " + access}}).status, 403u);
  // Not userinfo: there is no person.
  EXPECT_EQ(rig.request(verb::get, "/oauth2/userinfo", {}, {{"Authorization", "Bearer " + access}}).status, 401u);

  const auto too_much =
      rig.request(verb::post, "/oauth2/token", {{"grant_type", "client_credentials"}, {"scope", "lugh:apps.write"}}, {{"Authorization", basic(id, secret)}});
  EXPECT_EQ(boost::json::parse(too_much.body).at("error"), "invalid_scope");
  // A bad token is no caller, and never falls back to a session.
  EXPECT_EQ(rig.request(verb::get, "/api/v1/users", {}, {{"Authorization", "Bearer " + access + "x"}}).status, 401u);
}

// private_key_jwt: an assertion signed with a key the client registered, used once.
TEST_F(OAuthFlowTest, PrivateKeyJwt) {
  const auto key = lugh::tokens::SigningKey::generate(lugh::tokens::SigningAlgorithm::es256);
  const auto jwk = *lugh::tokens::public_jwk({"k1", lugh::tokens::SigningAlgorithm::es256, key.public_key()});
  lugh::apps::App draft;
  draft.name = "hub";
  draft.kind = lugh::apps::Kind::service;
  draft.auth = lugh::apps::ClientAuth::private_key_jwt;
  draft.jwks = boost::json::serialize(boost::json::object{{"keys", boost::json::array{jwk}}});
  draft.grants = lugh::apps::kClientCredentials;
  draft.client_scopes = {"lugh:directory.read"};
  draft.audiences = {"lugh"};
  const auto made = wait_for<lugh::Outcome<lugh::apps::Apps::Made>>(
      [&](lugh::Executor executor, auto done) { rig.apps->create(rig.admin, draft, kTestDeadline, executor, done); });
  ASSERT_TRUE(made.ok()) << made.message;
  const auto id = made.value.app.client_id;
  const auto now = rig.wall.unix_ms() / 1000;
  const auto assertion = [&](const std::string& jti, std::uint64_t exp, const std::string& aud) {
    return lugh::tokens::jws_sign(key, "k1", "JWT", boost::json::object{{"iss", id}, {"sub", id}, {"aud", aud}, {"exp", exp}, {"jti", jti}});
  };
  const auto ask = [&](const std::string& signed_assertion) {
    return rig.request(verb::post, "/oauth2/token",
                       {{"grant_type", "client_credentials"},
                        {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
                        {"client_assertion", signed_assertion}});
  };
  const std::string endpoint = std::string(SigninRig::kIssuer) + "/oauth2/token";
  EXPECT_EQ(ask(assertion("j1", now + 60, endpoint)).status, 200u);
  EXPECT_EQ(ask(assertion("j1", now + 60, endpoint)).status, 401u);
  EXPECT_EQ(ask(assertion("j2", now + 60, "https://elsewhere.example.com")).status, 401u);
  EXPECT_EQ(ask(assertion("j3", now - 1, endpoint)).status, 401u);
  EXPECT_EQ(ask(assertion("j4", now + 3600, endpoint)).status, 401u);
  const auto stranger = lugh::tokens::SigningKey::generate(lugh::tokens::SigningAlgorithm::es256);
  EXPECT_EQ(
      ask(lugh::tokens::jws_sign(stranger, "k1", "JWT", boost::json::object{{"iss", id}, {"sub", id}, {"aud", endpoint}, {"exp", now + 60}, {"jti", "j5"}}))
          .status,
      401u);
}

// RFC 9126: the parameters pushed by an authenticated client, used by reference once.
TEST_F(OAuthFlowTest, PushedAuthorizationRequests) {
  const auto [app, secret] = register_web();
  const auto pushed = rig.request(verb::post, "/oauth2/par",
                                  {{"response_type", "code"},
                                   {"redirect_uri", kRedirect},
                                   {"scope", "openid"},
                                   {"state", "p1"},
                                   {"nonce", "n1"},
                                   {"code_challenge", kChallenge},
                                   {"code_challenge_method", "S256"}},
                                  {{"Authorization", basic(app.client_id, secret)}});
  ASSERT_EQ(pushed.status, 201u) << pushed.body;
  const auto uri = std::string(boost::json::parse(pushed.body).at("request_uri").as_string());
  EXPECT_EQ(uri.rfind("urn:ietf:params:oauth:request_uri:", 0), 0u);
  const auto target = "/oauth2/authorize?client_id=" + app.client_id + "&request_uri=" + dannan::encoding::percent_encode(uri);
  const auto first = rig.get(target);
  EXPECT_EQ(first.location().rfind("/signin?continue=", 0), 0u) << first.body;
  // Used once.
  EXPECT_EQ(rig.get(target).status, 400u);
  // Refused without the client's credential.
  EXPECT_EQ(rig.request(verb::post, "/oauth2/par", {{"response_type", "code"}, {"client_id", app.client_id}}).status, 401u);
}

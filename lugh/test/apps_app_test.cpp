//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/apps/app.h"

#include <gtest/gtest.h>

using namespace lugh::apps;
using lugh::Fault;

namespace {

const std::string kJwks =
    R"({"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]})";

App web() {
  App app;
  app.name = "blackraven-admin";
  app.kind = Kind::web;
  app.auth = ClientAuth::private_key_jwt;
  app.jwks = kJwks;
  app.grants = kAuthorizationCode | kRefreshToken;
  app.redirect_uris = {"https://admin.example.com/callback"};
  app.scopes = {"openid", "profile"};
  app.audiences = {"lugh"};
  return app;
}

App api(const std::string& prefix) {
  App app;
  app.name = prefix;
  app.kind = Kind::api;
  app.prefix = prefix;
  return app;
}

Fault fault_of(const App& app, bool allow_secrets = false) { return validate(app, allow_secrets).fault; }

}  // namespace

TEST(App, AWellFormedApplicationOfEachKind) {
  EXPECT_TRUE(validate(web(), false).ok()) << validate(web(), false).message;
  EXPECT_TRUE(validate(api("toms"), false).ok()) << validate(api("toms"), false).message;

  App spa = web();
  spa.kind = Kind::spa;
  spa.auth = ClientAuth::none;
  spa.jwks.clear();
  EXPECT_TRUE(validate(spa, false).ok()) << validate(spa, false).message;

  App tv = spa;
  tv.kind = Kind::native;
  tv.grants = kDeviceCode | kRefreshToken;
  tv.redirect_uris.clear();
  EXPECT_TRUE(validate(tv, false).ok()) << validate(tv, false).message;

  App hub;
  hub.name = "hub";
  hub.kind = Kind::service;
  hub.auth = ClientAuth::tls_client_auth;
  hub.tls_subject = "CN=hub,O=Blackraven";
  hub.grants = kClientCredentials;
  hub.client_scopes = {"toms:dns"};
  hub.audiences = {"toms"};
  EXPECT_TRUE(validate(hub, false).ok()) << validate(hub, false).message;
}

// Public clients use PKCE and nothing else; confidential ones authenticate; a client secret
// only where policy allows it (docs/architecture.md, "OAuth profile").
TEST(App, ClientAuthenticationByKind) {
  App spa = web();
  spa.kind = Kind::spa;
  EXPECT_EQ(fault_of(spa), Fault::invalid);

  App none = web();
  none.auth = ClientAuth::none;
  none.jwks.clear();
  EXPECT_EQ(fault_of(none), Fault::invalid);

  App secret = web();
  secret.auth = ClientAuth::client_secret_basic;
  secret.jwks.clear();
  EXPECT_EQ(fault_of(secret), Fault::invalid);
  EXPECT_TRUE(validate(secret, true).ok());

  App tls = web();
  tls.auth = ClientAuth::tls_client_auth;
  tls.jwks.clear();
  EXPECT_EQ(fault_of(tls), Fault::invalid);
  tls.tls_thumbprint = std::string(43, 'A');
  EXPECT_TRUE(validate(tls, false).ok());
  tls.tls_subject = "CN=x";
  EXPECT_EQ(fault_of(tls), Fault::invalid);
  tls.tls_subject.clear();
  tls.tls_thumbprint = "short";
  EXPECT_EQ(fault_of(tls), Fault::invalid);
}

TEST(App, AJwkSetOfPublicKeysOnly) {
  App app = web();
  for (const auto* jwks : {"", "not json", "[]", R"({"keys":[]})", R"({"keys":[{"kty":"RSA","n":"x","e":"AQAB"}]})", R"({"keys":["EC"]})",
                           R"({"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"private"}]})"}) {
    app.jwks = jwks;
    EXPECT_EQ(fault_of(app), Fault::invalid) << jwks;
  }
  app.jwks = R"({"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]})";
  EXPECT_TRUE(validate(app, false).ok());
}

// Redirect URIs are matched exactly, so they are written exactly: https, no fragment, no user
// information; loopback http only for a native app (RFC 8252 section 7.3).
TEST(App, RedirectUris) {
  for (const auto* good : {"https://a.example.com/cb", "https://a.example.com:8443/cb?x=1", "https://[2001:db8::1]/cb", "https://a.example.com"}) {
    EXPECT_TRUE(redirect_uri_ok(good, Kind::web)) << good;
  }
  for (const auto* bad : {"http://a.example.com/cb", "https://a.example.com/cb#frag", "https://user@a.example.com/cb", "https:///cb", "https://a b/cb",
                          "com.example.app:/cb", "https://a.example.com:80x/", "HTTPS://a.example.com/cb", "https://a.example.com/caf\xc3\xa9"}) {
    EXPECT_FALSE(redirect_uri_ok(bad, Kind::web)) << bad;
  }
  EXPECT_TRUE(redirect_uri_ok("http://127.0.0.1/cb", Kind::native));
  EXPECT_TRUE(redirect_uri_ok("http://127.0.0.1:51004/cb", Kind::native));
  EXPECT_TRUE(redirect_uri_ok("http://[::1]:51004/cb", Kind::native));
  EXPECT_FALSE(redirect_uri_ok("http://localhost/cb", Kind::native));
  EXPECT_FALSE(redirect_uri_ok("http://127.0.0.1/cb", Kind::spa));
  EXPECT_FALSE(redirect_uri_ok(std::string("https://a.example.com/") + std::string(2048, 'a'), Kind::web));

  App app = web();
  app.redirect_uris = {"https://a.example.com/cb", "https://a.example.com/cb"};
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.redirect_uris.clear();
  EXPECT_EQ(fault_of(app), Fault::invalid);
}

TEST(App, GrantsByKind) {
  EXPECT_EQ(grants_allowed(Kind::spa), kAuthorizationCode | kRefreshToken);
  EXPECT_EQ(grants_allowed(Kind::service), kClientCredentials);

  App app = web();
  app.grants |= kDeviceCode;
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.grants = kRefreshToken;
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.grants = 0;
  EXPECT_EQ(fault_of(app), Fault::invalid);

  // Redirect and logout URIs belong to an app that signs users in.
  App service = web();
  service.grants = kClientCredentials;
  EXPECT_EQ(fault_of(service), Fault::invalid);
  service.redirect_uris.clear();
  EXPECT_TRUE(validate(service, false).ok());
  service.client_scopes = {"lugh:audit.read"};
  EXPECT_TRUE(validate(service, false).ok());
  App signer = web();
  signer.client_scopes = {"lugh:audit.read"};
  EXPECT_EQ(fault_of(signer), Fault::invalid);
}

TEST(App, PrefixesAndAudiences) {
  EXPECT_EQ(fault_of(api("lugh")), Fault::invalid);
  EXPECT_EQ(fault_of(api("Toms")), Fault::invalid);
  EXPECT_EQ(fault_of(api("")), Fault::invalid);
  App prefixed = web();
  prefixed.prefix = "admin";
  EXPECT_EQ(fault_of(prefixed), Fault::invalid);

  App app = web();
  app.audiences = {"lugh", "Not A Prefix"};
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.audiences = {"lugh", "toms"};
  EXPECT_TRUE(validate(app, false).ok());
  app.scopes = {"openid", "two words"};
  EXPECT_EQ(fault_of(app), Fault::invalid);
}

TEST(App, RolesAssuranceAndLifetimes) {
  App app = web();
  app.roles = {RoleMapping{"g1", {"manage_users", "media.viewer"}}};
  EXPECT_TRUE(validate(app, false).ok());
  app.roles = {RoleMapping{"g1", {}}};
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.roles = {RoleMapping{"g1", {"no spaces"}}};
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.roles.clear();

  app.acr = "urn:lugh:acr:phr";
  EXPECT_TRUE(validate(app, false).ok());
  app.acr = "urn:lugh:acr:best";
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.acr.clear();

  app.access_seconds = 59;
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.access_seconds = 300;
  app.refresh_idle_seconds = app.refresh_absolute_seconds + 1;
  EXPECT_EQ(fault_of(app), Fault::invalid);
  app.refresh_idle_seconds = 300;
  app.max_age = 366 * 86400;
  EXPECT_EQ(fault_of(app), Fault::invalid);
}

TEST(App, RoundTripsAndRefusesWhatEncodingWouldNotMake) {
  App app = web();
  app.icon_uri = "https://admin.example.com/icon.png";
  app.post_logout_uris = {"https://admin.example.com/bye"};
  app.backchannel_logout_uri = "https://admin.example.com/logout";
  app.access = {"g1", "g2"};
  app.roles = {RoleMapping{"g1", {"admin"}}};
  app.acr = "urn:lugh:acr:mfa";
  app.max_age = 3600;
  app.first_party = true;
  app.sender = SenderConstraint::dpop;
  app.state = State::disabled;
  app.created = 1;
  app.updated = 2;
  const auto hash = lugh::authn::hash_password(std::vector<unsigned char>{'s'}, {64, 1, 1});
  ASSERT_TRUE(hash.ok);
  app.secrets = {ClientSecret{hash.value, 0}, ClientSecret{hash.value, 99}};

  const auto bytes = encode(app);
  const auto back = decode(bytes);
  ASSERT_TRUE(back);
  EXPECT_EQ(encode(*back), bytes);
  EXPECT_EQ(back->name, app.name);
  EXPECT_EQ(back->roles, app.roles);
  EXPECT_EQ(back->secrets.size(), 2u);
  EXPECT_EQ(back->secrets[1].expires, 99u);
  EXPECT_EQ(back->state, State::disabled);

  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(decode(longer));
  EXPECT_FALSE(decode(std::span(bytes).first(bytes.size() - 1)));
  auto format = bytes;
  format[0] = 2;
  EXPECT_FALSE(decode(format));
}

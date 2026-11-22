//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh::client::OAuthClient, P10.3a (TODO/2026-11-14-p10-plan.md): endpoints from discovery; the
// authorisation request with PKCE S256 (RFC 7636), state and nonce, pushed when asked (RFC 9126);
// the return checked for its issuer (RFC 9207), state and error; the code redeemed and the ID token
// verified with its nonce (OIDC Core 3.1.3.7); refresh; client credentials; the client
// authenticated as registered: public, private_key_jwt (RFC 7523) or client_secret_basic (RFC 6749
// section 2.3.1). Each request is checked as the issuer would receive it.

#include <gtest/gtest.h>

#include <algorithm>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <deque>
#include <map>

#include "dannan/encoding/percent.h"
#include "dannan/identity/crypto.h"
#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/jose.h"
#include "lugh/client/oauth_client.h"
#include "lugh/core/encoding.h"
#include "lugh/oauth/dpop.h"
#include "lugh/test/fixtures/recording_https.h"

using namespace lugh::client;
using dannan::identity::Secret;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kIssuer = "https://lugh.example";
constexpr const char* kRedirect = "https://app.example/back";
constexpr const char* kTokenUrl = "https://lugh.example/oauth2/token";

boost::json::object discovery() {
  return {{"issuer", kIssuer},
          {"authorization_endpoint", std::string(kIssuer) + "/oauth2/authorize"},
          {"token_endpoint", std::string(kIssuer) + "/oauth2/token"},
          {"pushed_authorization_request_endpoint", std::string(kIssuer) + "/oauth2/par"},
          {"device_authorization_endpoint", std::string(kIssuer) + "/oauth2/device"},
          {"userinfo_endpoint", std::string(kIssuer) + "/oauth2/userinfo"},
          {"introspection_endpoint", std::string(kIssuer) + "/oauth2/introspect"},
          {"revocation_endpoint", std::string(kIssuer) + "/oauth2/revoke"},
          {"end_session_endpoint", std::string(kIssuer) + "/oauth2/logout"},
          {"jwks_uri", std::string(kIssuer) + "/oauth2/jwks"},
          {"mtls_endpoint_aliases",
           {{"token_endpoint", "https://lugh.example:8443/oauth2/token"}, {"pushed_authorization_request_endpoint", "https://lugh.example:8443/oauth2/par"}}}};
}

class OAuthTest : public ::testing::Test {
 protected:
  OAuthTest() {
    boost::json::array keys;
    keys.push_back(*public_jwk({"k1", SigningAlgorithm::es256, site_key.public_key()}));
    verifier.set_keys(kIssuer, {{"keys", keys}});
  }

  OAuthClient client(ClientIdentity identity) {
    return OAuthClient(std::get<Endpoints>(Endpoints::from_discovery(discovery(), kIssuer)), std::move(identity), https, verifier, wall);
  }

  static ClientIdentity public_client() {
    ClientIdentity identity;
    identity.client_id = "app1";
    return identity;
  }

  // One literal: GCC 14 at -O2 misreads the concatenation of two as writing past the string.
  std::string token_url() const { return kTokenUrl; }

  std::string id_token(const std::string& nonce) const {
    return jws_sign(site_key, "k1", "JWT",
                    {{"iss", kIssuer}, {"sub", "u1"}, {"aud", "app1"}, {"azp", "app1"}, {"iat", kNow}, {"exp", kNow + 300}, {"nonce", nonce}});
  }

  template <typename T>
  lugh::Outcome<T> wait(std::function<void(lugh::Done<lugh::Outcome<T>>)> call) {
    std::optional<lugh::Outcome<T>> out;
    call([&](lugh::Outcome<T> answer) { out = std::move(answer); });
    io.restart();
    io.run();
    return std::move(*out);
  }

  lugh::Outcome<TokenSet> redeem(OAuthClient& oauth, const AuthorizationRequest& request) {
    return wait<TokenSet>([&](auto done) { oauth.redeem("c1", request, std::chrono::seconds(5), io.get_executor(), done); });
  }

  // Runs the io_context until `done` holds, or long enough that it never will.
  template <typename Predicate>
  bool pump(Predicate done) {
    for (int i = 0; i < 400 && !done(); ++i) {
      io.restart();
      io.run_for(std::chrono::milliseconds(5));
    }
    return done();
  }

  // Runs the io_context a while, for what should not happen.
  void settle() {
    for (int i = 0; i < 20; ++i) {
      io.restart();
      io.run_for(std::chrono::milliseconds(5));
    }
  }

  std::string device_url() const { return std::string(kIssuer) + "/oauth2/device"; }

  // Until the `n`th poll is sent and its answer taken, before time moves on: the next wait is
  // measured from the answer.
  bool polled(std::size_t n) {
    if (!pump([&] { return https.sent_to(token_url()) == n; })) return false;
    settle();
    return https.sent_to(token_url()) == n;
  }

  DeviceAuthorization started(std::uint32_t expires_in = 600, std::uint32_t interval = 5) {
    DeviceAuthorization out;
    out.device_code = std::make_shared<Secret>(lugh::byte_span("dc-1"));
    out.user_code = "WDJB-MJHT";
    out.verification_uri = std::string(kIssuer) + "/device";
    out.expires_in = expires_in;
    out.interval = interval;
    return out;
  }

  boost::asio::io_context io;
  dannan::test::SteppedTime time;
  dannan::test::SteppedWall wall{kNow * 1000};
  SigningKey site_key = SigningKey::generate(SigningAlgorithm::es256);
  Verifier verifier{{kIssuer}, wall};
  RecordingHttps https;
};

}  // namespace

TEST_F(OAuthTest, EndpointsComeFromTheIssuersOwnDiscovery) {
  const auto found = Endpoints::from_discovery(discovery(), kIssuer);
  ASSERT_TRUE(std::holds_alternative<Endpoints>(found));
  const auto& endpoints = std::get<Endpoints>(found);
  EXPECT_EQ(endpoints.token, std::string(kIssuer) + "/oauth2/token");
  EXPECT_EQ(endpoints.pushed_authorization, std::string(kIssuer) + "/oauth2/par");
  EXPECT_EQ(endpoints.end_session, std::string(kIssuer) + "/oauth2/logout");

  EXPECT_EQ(std::get<std::string>(Endpoints::from_discovery(discovery(), "https://other.example")), "the discovery document names another issuer");
  auto plain = discovery();
  plain["token_endpoint"] = "http://lugh.example/oauth2/token";
  EXPECT_EQ(std::get<std::string>(Endpoints::from_discovery(plain, kIssuer)), "the discovery document has no https authorization or token endpoint");
}

TEST_F(OAuthTest, AClientNeedsWhatItsMethodNeeds) {
  ClientIdentity none;
  EXPECT_THROW(client(none), std::invalid_argument);
  auto jwt = public_client();
  jwt.method = ClientIdentity::Method::private_key_jwt;
  EXPECT_THROW(client(jwt), std::invalid_argument);
  auto basic = public_client();
  basic.method = ClientIdentity::Method::client_secret_basic;
  EXPECT_THROW(client(basic), std::invalid_argument);
}

TEST_F(OAuthTest, AnAuthorizationRequestCarriesPkceStateAndNonce) {
  auto oauth = client(public_client());
  const auto request = oauth.authorization(kRedirect, {"openid", "lir:sub:a/%2B"});
  ASSERT_EQ(request.url.rfind(std::string(kIssuer) + "/oauth2/authorize?", 0), 0u);
  const auto fields = fields_of(std::string_view(request.url).substr(request.url.find('?') + 1));
  EXPECT_EQ(fields.at("response_type"), "code");
  EXPECT_EQ(fields.at("client_id"), "app1");
  EXPECT_EQ(fields.at("redirect_uri"), kRedirect);
  EXPECT_EQ(fields.at("scope"), "openid lir:sub:a/%2B");
  EXPECT_EQ(fields.at("state"), request.state);
  EXPECT_EQ(fields.at("nonce"), request.nonce);
  EXPECT_EQ(fields.at("code_challenge_method"), "S256");
  // RFC 7636 4.1 and 4.2: 43 unreserved characters, and the challenge their SHA-256.
  const auto code_verifier = text_of(*request.code_verifier);
  EXPECT_EQ(code_verifier.size(), 43u);
  EXPECT_EQ(fields.at("code_challenge"), lugh::encoding::base64url(dannan::identity::sha256(request.code_verifier->reveal()).bytes));
  // Each request is fresh.
  const auto again = oauth.authorization(kRedirect, {"openid"});
  EXPECT_NE(again.state, request.state);
  EXPECT_NE(again.nonce, request.nonce);
  EXPECT_NE(text_of(*again.code_verifier), code_verifier);
}

TEST_F(OAuthTest, TheReturnIsCheckedForIssuerStateAndError) {
  auto oauth = client(public_client());
  const auto request = oauth.authorization(kRedirect, {"openid"});
  const auto with = [&](const std::string& rest) { return "iss=" + dannan::encoding::percent_encode(kIssuer, dannan::encoding::PercentSet::form()) + rest; };

  const auto good = oauth.callback(with("&state=" + request.state + "&code=c1"), request);
  ASSERT_TRUE(good.ok()) << good.message;
  EXPECT_EQ(good.value, "c1");
  EXPECT_EQ(oauth.callback(with("&state=other&code=c1"), request).fault, lugh::Fault::refused);
  EXPECT_EQ(oauth.callback("state=" + request.state + "&code=c1", request).message, "the return is not from this issuer");
  EXPECT_EQ(oauth.callback("iss=https%3A%2F%2Fother.example&state=" + request.state + "&code=c1", request).fault, lugh::Fault::refused);
  const auto denied = oauth.callback(with("&state=" + request.state + "&error=access_denied&error_description=the+person+said+no"), request);
  EXPECT_EQ(denied.fault, lugh::Fault::refused);
  EXPECT_EQ(denied.message, "access_denied: the person said no");
  EXPECT_EQ(oauth.callback(with("&state=" + request.state), request).fault, lugh::Fault::invalid);
  EXPECT_EQ(oauth.callback("iss=%zz", request).fault, lugh::Fault::invalid);
}

TEST_F(OAuthTest, TheCodeIsRedeemedAndTheIdTokenVerifiedWithItsNonce) {
  auto oauth = client(public_client());
  const auto request = oauth.authorization(kRedirect, {"openid"});
  https.answer(token_url(), 200,
               {{"access_token", "at-1"},
                {"token_type", "Bearer"},
                {"expires_in", 300},
                {"scope", "openid"},
                {"refresh_token", "rt-1"},
                {"id_token", id_token(request.nonce)}});
  const auto tokens = redeem(oauth, request);
  ASSERT_TRUE(tokens.ok()) << tokens.message;
  EXPECT_EQ(text_of(*tokens.value.access_token), "at-1");
  EXPECT_EQ(tokens.value.token_type, "Bearer");
  EXPECT_EQ(tokens.value.expires_in, 300u);
  EXPECT_EQ(tokens.value.scopes, std::vector<std::string>{"openid"});
  EXPECT_EQ(text_of(*tokens.value.refresh_token), "rt-1");
  ASSERT_TRUE(tokens.value.id_token);
  EXPECT_EQ(tokens.value.id_token->subject, "u1");

  ASSERT_EQ(https.sent().size(), 1u);
  EXPECT_EQ(https.sent()[0].method, "POST");
  EXPECT_EQ(https.sent()[0].content_type, "application/x-www-form-urlencoded");
  const auto fields = fields_of(https.sent()[0].body);
  EXPECT_EQ(fields.at("grant_type"), "authorization_code");
  EXPECT_EQ(fields.at("code"), "c1");
  EXPECT_EQ(fields.at("redirect_uri"), kRedirect);
  EXPECT_EQ(fields.at("code_verifier"), text_of(*request.code_verifier));
  EXPECT_EQ(fields.at("client_id"), "app1");

  // An ID token for another request's nonce is refused, tokens and all.
  https.answer(token_url(), 200, {{"access_token", "at-2"}, {"token_type", "Bearer"}, {"id_token", id_token("another")}});
  const auto mixed = redeem(oauth, request);
  EXPECT_EQ(mixed.fault, lugh::Fault::refused);
  EXPECT_EQ(mixed.message, "the ID token: not the nonce sent");
}

TEST_F(OAuthTest, TheTokenEndpointsErrorIsARefusal) {
  auto oauth = client(public_client());
  const auto request = oauth.authorization(kRedirect, {"openid"});
  https.answer(token_url(), 400, {{"error", "invalid_grant"}, {"error_description", "the code is not good"}});
  const auto refused = redeem(oauth, request);
  EXPECT_EQ(refused.fault, lugh::Fault::refused);
  EXPECT_EQ(refused.message, "invalid_grant: the code is not good");

  https.forget_answers();
  EXPECT_EQ(redeem(oauth, request).fault, lugh::Fault::unavailable);
  https.answer(token_url(), 200, {{"token_type", "Bearer"}});
  const auto unread = redeem(oauth, request);
  EXPECT_EQ(unread.fault, lugh::Fault::invalid);
  EXPECT_EQ(unread.message, "the token endpoint's answer has no access_token");
}

TEST_F(OAuthTest, PrivateKeyJwtSignsAFreshAssertionForTheTokenEndpoint) {
  auto identity = public_client();
  identity.method = ClientIdentity::Method::private_key_jwt;
  auto key = std::make_shared<SigningKey>(SigningKey::generate(SigningAlgorithm::ed25519));
  identity.key = key;
  identity.kid = "c1";
  auto oauth = client(identity);
  https.answer(token_url(), 200, {{"access_token", "at-1"}, {"token_type", "Bearer"}});
  for (int i = 0; i < 2; ++i)
    ASSERT_TRUE(wait<TokenSet>([&](auto done) { oauth.client_credentials({"lir:pub:a"}, std::chrono::seconds(5), io.get_executor(), done); }).ok());

  std::vector<std::string> jtis;
  for (const auto& sent : https.sent()) {
    const auto fields = fields_of(sent.body);
    EXPECT_EQ(fields.at("grant_type"), "client_credentials");
    EXPECT_EQ(fields.at("scope"), "lir:pub:a");
    EXPECT_EQ(fields.at("client_id"), "app1");
    EXPECT_EQ(fields.at("client_assertion_type"), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    const auto jws = jws_parse(fields.at("client_assertion"));
    ASSERT_TRUE(jws);
    EXPECT_TRUE(jws_verify(*jws, {{"c1", SigningAlgorithm::ed25519, key->public_key()}}));
    EXPECT_EQ(jws->claims.at("iss").as_string(), "app1");
    EXPECT_EQ(jws->claims.at("sub").as_string(), "app1");
    EXPECT_EQ(std::string(jws->claims.at("aud").as_string()), token_url());
    EXPECT_EQ(jws->claims.at("exp").to_number<std::uint64_t>(), kNow + 60);
    jtis.emplace_back(jws->claims.at("jti").as_string());
  }
  ASSERT_EQ(jtis.size(), 2u);
  EXPECT_NE(jtis[0], jtis[1]);
}

TEST_F(OAuthTest, ClientSecretBasicGoesInTheHeaderFormEncoded) {
  auto identity = public_client();
  identity.client_id = "app:1";
  identity.method = ClientIdentity::Method::client_secret_basic;
  identity.secret = std::make_shared<Secret>(lugh::byte_span("s+cret word"));
  auto oauth = client(identity);
  https.answer(token_url(), 200, {{"access_token", "at-1"}, {"token_type", "Bearer"}});
  ASSERT_TRUE(wait<TokenSet>([&](auto done) { oauth.client_credentials({}, std::chrono::seconds(5), io.get_executor(), done); }).ok());
  // RFC 6749 2.3.1: each part form-encoded before the pair is base64'd.
  EXPECT_EQ(https.header(0, "Authorization"), "Basic " + lugh::encoding::base64(lugh::byte_span("app%3A1:s%2Bcret+word")));
  const auto fields = fields_of(https.sent()[0].body);
  EXPECT_FALSE(fields.count("client_id"));
  EXPECT_FALSE(fields.count("client_secret"));
  EXPECT_FALSE(fields.count("scope"));
}

TEST_F(OAuthTest, ARefreshSendsItsTokenAndTheNarrowedScopes) {
  auto oauth = client(public_client());
  https.answer(token_url(), 200, {{"access_token", "at-2"}, {"token_type", "Bearer"}, {"refresh_token", "rt-2"}, {"scope", "openid"}});
  const Secret old(lugh::byte_span("rt-1"));
  const auto tokens = wait<TokenSet>([&](auto done) { oauth.refresh(old, {"openid"}, std::chrono::seconds(5), io.get_executor(), done); });
  ASSERT_TRUE(tokens.ok()) << tokens.message;
  EXPECT_EQ(text_of(*tokens.value.refresh_token), "rt-2");
  const auto fields = fields_of(https.sent()[0].body);
  EXPECT_EQ(fields.at("grant_type"), "refresh_token");
  EXPECT_EQ(fields.at("refresh_token"), "rt-1");
  EXPECT_EQ(fields.at("scope"), "openid");
}

TEST_F(OAuthTest, APushedRequestLeavesOnlyItsUriInTheUrl) {
  auto oauth = client(public_client());
  const auto par = std::string(kIssuer) + "/oauth2/par";
  https.answer(par, 201, {{"request_uri", "urn:ietf:params:oauth:request_uri:abc"}, {"expires_in", 60}});
  const auto pushed =
      wait<AuthorizationRequest>([&](auto done) { oauth.pushed_authorization(kRedirect, {"openid"}, std::chrono::seconds(5), io.get_executor(), done); });
  ASSERT_TRUE(pushed.ok()) << pushed.message;
  const auto fields = fields_of(std::string_view(pushed.value.url).substr(pushed.value.url.find('?') + 1));
  EXPECT_EQ(fields.size(), 2u);
  EXPECT_EQ(fields.at("client_id"), "app1");
  EXPECT_EQ(fields.at("request_uri"), "urn:ietf:params:oauth:request_uri:abc");

  // What was pushed: the whole request, the client named once.
  const auto pushed_request = https.sent().at(0);
  const auto sent = fields_of(pushed_request.body);
  EXPECT_EQ(pushed_request.url, par);
  EXPECT_EQ(sent.at("client_id"), "app1");
  EXPECT_EQ(sent.at("state"), pushed.value.state);
  EXPECT_EQ(sent.at("nonce"), pushed.value.nonce);
  EXPECT_EQ(sent.at("code_challenge_method"), "S256");
  EXPECT_EQ(std::count(pushed_request.body.begin(), pushed_request.body.end(), '&') + 1, static_cast<long>(sent.size()));

  https.answer(par, 400, {{"error", "invalid_scope"}, {"error_description", "not this client's"}});
  const auto refused =
      wait<AuthorizationRequest>([&](auto done) { oauth.pushed_authorization(kRedirect, {"nope"}, std::chrono::seconds(5), io.get_executor(), done); });
  EXPECT_EQ(refused.fault, lugh::Fault::refused);
  EXPECT_EQ(refused.message, "invalid_scope: not this client's");
}

TEST_F(OAuthTest, ADeviceAuthorizationIsBegun) {
  auto oauth = client(public_client());
  https.answer(device_url(), 200,
               {{"device_code", "dc-1"},
                {"user_code", "WDJB-MJHT"},
                {"verification_uri", std::string(kIssuer) + "/device"},
                {"verification_uri_complete", std::string(kIssuer) + "/device?user_code=WDJB-MJHT"},
                {"expires_in", 600}});
  const auto begun = wait<DeviceAuthorization>([&](auto done) { oauth.device_authorization({"openid"}, std::chrono::seconds(5), io.get_executor(), done); });
  ASSERT_TRUE(begun.ok()) << begun.message;
  EXPECT_EQ(text_of(*begun.value.device_code), "dc-1");
  EXPECT_EQ(begun.value.user_code, "WDJB-MJHT");
  EXPECT_EQ(begun.value.verification_uri_complete, std::string(kIssuer) + "/device?user_code=WDJB-MJHT");
  EXPECT_EQ(begun.value.expires_in, 600u);
  // RFC 8628 3.2: five seconds when the issuer names no interval.
  EXPECT_EQ(begun.value.interval, 5u);
  const auto fields = fields_of(https.sent()[0].body);
  EXPECT_EQ(fields.at("scope"), "openid");
  EXPECT_EQ(fields.at("client_id"), "app1");
}

// RFC 8628 3.4 and 3.5: the first poll an interval after the start; authorization_pending waits
// the interval again; slow_down adds five seconds to it; tokens end it.
TEST_F(OAuthTest, TheTokenEndpointIsPolledAtTheIntervalUntilTokensCome) {
  auto oauth = client(public_client());
  https.queue(token_url(), 400, {{"error", "authorization_pending"}});
  https.queue(token_url(), 400, {{"error", "slow_down"}});
  https.queue(token_url(), 400, {{"error", "authorization_pending"}});
  https.queue(token_url(), 200, {{"access_token", "at-1"}, {"token_type", "Bearer"}});
  std::optional<lugh::Outcome<TokenSet>> out;
  oauth.device_tokens(started(), time, std::chrono::seconds(5), io.get_executor(), [&](lugh::Outcome<TokenSet> got) { out = std::move(got); });

  const auto polls = [&] { return https.sent_to(token_url()); };
  settle();
  EXPECT_EQ(polls(), 0u);
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(polled(1));
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(polled(2));
  // slow_down: the interval is ten seconds now.
  time.advance(std::chrono::seconds(5));
  settle();
  EXPECT_EQ(polls(), 2u);
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(polled(3));
  time.advance(std::chrono::seconds(10));
  ASSERT_TRUE(pump([&] { return out.has_value(); }));
  ASSERT_TRUE(out->ok()) << out->message;
  EXPECT_EQ(text_of(*out->value.access_token), "at-1");
  const auto fields = fields_of(https.sent().back().body);
  EXPECT_EQ(fields.at("grant_type"), "urn:ietf:params:oauth:grant-type:device_code");
  EXPECT_EQ(fields.at("device_code"), "dc-1");
}

TEST_F(OAuthTest, ARefusalEndsThePolling) {
  auto oauth = client(public_client());
  https.queue(token_url(), 400, {{"error", "access_denied"}, {"error_description", "the user did not allow it"}});
  std::optional<lugh::Outcome<TokenSet>> out;
  oauth.device_tokens(started(), time, std::chrono::seconds(5), io.get_executor(), [&](lugh::Outcome<TokenSet> got) { out = std::move(got); });
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(pump([&] { return out.has_value(); }));
  EXPECT_EQ(out->fault, lugh::Fault::refused);
  EXPECT_EQ(out->message, "access_denied: the user did not allow it");
  time.advance(std::chrono::seconds(60));
  settle();
  EXPECT_EQ(https.sent_to(token_url()), 1u);
}

TEST_F(OAuthTest, PollingStopsWhenTheCodeExpires) {
  auto oauth = client(public_client());
  https.answer(token_url(), 400, {{"error", "authorization_pending"}});
  std::optional<lugh::Outcome<TokenSet>> out;
  oauth.device_tokens(started(12, 5), time, std::chrono::seconds(5), io.get_executor(), [&](lugh::Outcome<TokenSet> got) { out = std::move(got); });
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(polled(1));
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(polled(2));
  // Fifteen seconds in, past the twelve: refused without another poll.
  time.advance(std::chrono::seconds(5));
  ASSERT_TRUE(pump([&] { return out.has_value(); }));
  EXPECT_EQ(out->fault, lugh::Fault::refused);
  EXPECT_EQ(out->message.rfind("expired_token:", 0), 0u);
  EXPECT_EQ(https.sent_to(token_url()), 2u);
}

// RFC 9449: a client with a DPoP key proves it on every token request, so its tokens are bound to
// the key; and proves it with the token's hash at a resource. The issuer's own checker judges.
TEST_F(OAuthTest, AClientWithADpopKeyProvesItOnEveryTokenRequest) {
  dannan::test::SteppedTime checker_time;
  lugh::oauth::DpopChecker checker{checker_time, wall};
  auto identity = public_client();
  auto key = std::make_shared<SigningKey>(SigningKey::generate(SigningAlgorithm::es256));
  identity.dpop_key = key;
  auto oauth = client(identity);
  https.answer(token_url(), 200, {{"access_token", "at-1"}, {"token_type", "DPoP"}});
  const Secret old(lugh::byte_span("rt-1"));
  ASSERT_TRUE(wait<TokenSet>([&](auto done) { oauth.refresh(old, {}, std::chrono::seconds(5), io.get_executor(), done); }).ok());
  const auto proof = https.header(0, "DPoP");
  ASSERT_FALSE(proof.empty());
  const auto checked = checker.check(proof, "POST", token_url());
  ASSERT_TRUE(checked.ok()) << checked.message;
  EXPECT_EQ(checked.value.jkt, lugh::oauth::jwk_thumbprint({"", SigningAlgorithm::es256, key->public_key()}));

  const std::string userinfo = std::string(kIssuer) + "/oauth2/userinfo";
  const auto resource = oauth.dpop_proof_for("GET", userinfo, "at-1");
  ASSERT_TRUE(resource);
  EXPECT_TRUE(checker.check(*resource, "GET", userinfo, "at-1").ok());
  EXPECT_FALSE(client(public_client()).dpop_proof_for("GET", userinfo, "at-1"));
}

// RFC 8705: a client presenting its certificate calls the issuer's mTLS aliases; with
// tls_client_auth the certificate is its credential and only its client_id goes in the form; a
// client bound to its certificate that authenticates otherwise calls the aliases too.
TEST_F(OAuthTest, AClientPresentingItsCertificateCallsTheMtlsAliases) {
  const auto endpoints = std::get<Endpoints>(Endpoints::from_discovery(discovery(), kIssuer));
  EXPECT_EQ(endpoints.mtls.token, "https://lugh.example:8443/oauth2/token");
  EXPECT_EQ(endpoints.mtls.pushed_authorization, "https://lugh.example:8443/oauth2/par");
  EXPECT_TRUE(endpoints.mtls.introspection.empty());

  auto tls = public_client();
  tls.method = ClientIdentity::Method::tls_client_auth;
  auto oauth = client(tls);
  https.answer("https://lugh.example:8443/oauth2/token", 200, {{"access_token", "at-1"}, {"token_type", "Bearer"}});
  ASSERT_TRUE(wait<TokenSet>([&](auto done) { oauth.client_credentials({}, std::chrono::seconds(5), io.get_executor(), done); }).ok());
  EXPECT_EQ(https.sent()[0].url, "https://lugh.example:8443/oauth2/token");
  const auto fields = fields_of(https.sent()[0].body);
  EXPECT_EQ(fields.at("client_id"), "app1");
  EXPECT_FALSE(fields.count("client_assertion"));
  EXPECT_TRUE(https.header(0, "Authorization").empty());

  auto bound = public_client();
  bound.method = ClientIdentity::Method::private_key_jwt;
  bound.key = std::make_shared<SigningKey>(SigningKey::generate(SigningAlgorithm::es256));
  bound.kid = "c1";
  bound.certificate_bound = true;
  auto bound_client = client(bound);
  ASSERT_TRUE(wait<TokenSet>([&](auto done) { bound_client.client_credentials({}, std::chrono::seconds(5), io.get_executor(), done); }).ok());
  EXPECT_EQ(https.sent()[1].url, "https://lugh.example:8443/oauth2/token");
  // The assertion is still for the token endpoint the issuer names.
  const auto assertion = jws_parse(fields_of(https.sent()[1].body).at("client_assertion"));
  ASSERT_TRUE(assertion);
  EXPECT_EQ(std::string(assertion->claims.at("aud").as_string()), token_url());

  // An issuer with no aliases: the endpoints as they are.
  auto plain = discovery();
  plain.erase("mtls_endpoint_aliases");
  OAuthClient without(std::get<Endpoints>(Endpoints::from_discovery(plain, kIssuer)), tls, https, verifier, wall);
  https.answer(token_url(), 200, {{"access_token", "at-2"}, {"token_type", "Bearer"}});
  ASSERT_TRUE(wait<TokenSet>([&](auto done) { without.client_credentials({}, std::chrono::seconds(5), io.get_executor(), done); }).ok());
  EXPECT_EQ(https.sent()[2].url, token_url());
}

// RFC 7662: the token sent, authenticated as the client is; the answer's claims read.
TEST_F(OAuthTest, IntrospectionSaysWhetherATokenIsActive) {
  auto identity = public_client();
  identity.method = ClientIdentity::Method::client_secret_basic;
  identity.secret = std::make_shared<Secret>(lugh::byte_span("s1"));
  auto oauth = client(identity);
  const auto url = std::string(kIssuer) + "/oauth2/introspect";
  https.answer(url, 200, {{"active", true}, {"token_type", "Bearer"}, {"sub", "u1"}, {"client_id", "app2"}, {"scope", "lir:sub:a openid"}, {"exp", kNow + 60}});
  const Secret token(lugh::byte_span("lo_handle"));
  const auto active = wait<Introspection>([&](auto done) { oauth.introspect(token, std::chrono::seconds(5), io.get_executor(), done); });
  ASSERT_TRUE(active.ok()) << active.message;
  EXPECT_TRUE(active.value.active);
  EXPECT_EQ(active.value.subject, "u1");
  EXPECT_EQ(active.value.client_id, "app2");
  EXPECT_EQ(active.value.scopes, (std::vector<std::string>{"lir:sub:a", "openid"}));
  EXPECT_EQ(active.value.expires, kNow + 60);
  EXPECT_EQ(fields_of(https.sent()[0].body).at("token"), "lo_handle");
  EXPECT_FALSE(https.header(0, "Authorization").empty());

  https.answer(url, 200, {{"active", false}});
  const auto inactive = wait<Introspection>([&](auto done) { oauth.introspect(token, std::chrono::seconds(5), io.get_executor(), done); });
  ASSERT_TRUE(inactive.ok());
  EXPECT_FALSE(inactive.value.active);

  // A public client may not ask.
  https.answer(url, 401, {{"error", "invalid_client"}, {"error_description", "a public client cannot introspect"}});
  const auto refused = wait<Introspection>([&](auto done) { oauth.introspect(token, std::chrono::seconds(5), io.get_executor(), done); });
  EXPECT_EQ(refused.fault, lugh::Fault::refused);
  EXPECT_EQ(refused.message.rfind("invalid_client:", 0), 0u);
  // An answer that does not say whether the token is active could not be read: invalid, as
  // Dannan's vocabulary names a reply it cannot read.
  https.answer(url, 200, {{"sub", "u1"}});
  EXPECT_EQ(wait<Introspection>([&](auto done) { oauth.introspect(token, std::chrono::seconds(5), io.get_executor(), done); }).fault, lugh::Fault::invalid);
}

// RFC 7009: the token sent; the issuer's 200 is the answer whether it knew the token or not.
TEST_F(OAuthTest, ATokenIsRevoked) {
  auto oauth = client(public_client());
  const auto url = std::string(kIssuer) + "/oauth2/revoke";
  https.answer(url, 200, {});
  const Secret token(lugh::byte_span("lr_family.secret"));
  ASSERT_TRUE(wait<lugh::Nothing>([&](auto done) { oauth.revoke(token, std::chrono::seconds(5), io.get_executor(), done); }).ok());
  const auto fields = fields_of(https.sent()[0].body);
  EXPECT_EQ(fields.at("token"), "lr_family.secret");
  EXPECT_EQ(fields.at("client_id"), "app1");

  https.answer(url, 401, {{"error", "invalid_client"}, {"error_description", "no such client"}});
  const auto refused = wait<lugh::Nothing>([&](auto done) { oauth.revoke(token, std::chrono::seconds(5), io.get_executor(), done); });
  EXPECT_EQ(refused.fault, lugh::Fault::refused);
  EXPECT_EQ(refused.message, "invalid_client: no such client");
  https.forget_answers();
  EXPECT_EQ(wait<lugh::Nothing>([&](auto done) { oauth.revoke(token, std::chrono::seconds(5), io.get_executor(), done); }).fault, lugh::Fault::unavailable);
}

// An issuer that does not publish an endpoint is not sent the request that needs it: the caller
// is told at once, and nothing goes out.
TEST_F(OAuthTest, AnEndpointTheIssuerDoesNotPublishIsNotCalled) {
  auto published = discovery();
  for (const auto* name : {"pushed_authorization_request_endpoint", "device_authorization_endpoint", "introspection_endpoint", "revocation_endpoint"})
    published.erase(name);
  published.erase("mtls_endpoint_aliases");
  auto identity = public_client();
  identity.method = ClientIdentity::Method::client_secret_basic;
  identity.secret = std::make_shared<Secret>(lugh::byte_span("s1"));
  OAuthClient oauth(std::get<Endpoints>(Endpoints::from_discovery(published, kIssuer)), identity, https, verifier, wall);
  const Secret token(lugh::byte_span("t"));
  EXPECT_EQ(
      wait<AuthorizationRequest>([&](auto done) { oauth.pushed_authorization(kRedirect, {"openid"}, std::chrono::seconds(5), io.get_executor(), done); }).fault,
      lugh::Fault::invalid);
  EXPECT_EQ(wait<DeviceAuthorization>([&](auto done) { oauth.device_authorization({"openid"}, std::chrono::seconds(5), io.get_executor(), done); }).fault,
            lugh::Fault::invalid);
  EXPECT_EQ(wait<Introspection>([&](auto done) { oauth.introspect(token, std::chrono::seconds(5), io.get_executor(), done); }).fault, lugh::Fault::invalid);
  EXPECT_EQ(wait<lugh::Nothing>([&](auto done) { oauth.revoke(token, std::chrono::seconds(5), io.get_executor(), done); }).fault, lugh::Fault::invalid);
  EXPECT_TRUE(https.sent().empty());
}

// RFC 8628 section 3.2: the device endpoint's error is the issuer's refusal, said as it said it.
TEST_F(OAuthTest, TheDeviceEndpointsErrorIsARefusal) {
  auto oauth = client(public_client());
  https.answer(device_url(), 400, {{"error", "invalid_scope"}, {"error_description", "not for this client"}});
  const auto refused = wait<DeviceAuthorization>([&](auto done) { oauth.device_authorization({"openid"}, std::chrono::seconds(5), io.get_executor(), done); });
  EXPECT_EQ(refused.fault, lugh::Fault::refused);
  EXPECT_EQ(refused.message, "invalid_scope: not for this client");
}

// An answer that is no OAuth error (a proxy's page, say) is not a refusal: a 503 says the
// issuer is unavailable, anything else that it failed.
TEST_F(OAuthTest, ARevocationAnsweredWithSomethingElseFailed) {
  auto oauth = client(public_client());
  HttpsResponse busy;
  busy.status = 503;
  busy.content_type = "text/html";
  busy.body = "<p>busy</p>";
  https.answer(std::string(kIssuer) + "/oauth2/revoke", busy);
  const Secret token(lugh::byte_span("t"));
  const auto failed = wait<lugh::Nothing>([&](auto done) { oauth.revoke(token, std::chrono::seconds(5), io.get_executor(), done); });
  EXPECT_EQ(failed.fault, lugh::Fault::unavailable);
  EXPECT_EQ(failed.message, "the revocation endpoint answered 503");
  busy.status = 502;
  https.answer(std::string(kIssuer) + "/oauth2/revoke", busy);
  EXPECT_EQ(wait<lugh::Nothing>([&](auto done) { oauth.revoke(token, std::chrono::seconds(5), io.get_executor(), done); }).fault, lugh::Fault::failed);
}

// RFC 6749 section 3.3: the granted scope is a space-separated list, read word by word.
TEST_F(OAuthTest, TheGrantedScopesAreReadWordByWord) {
  auto identity = public_client();
  identity.method = ClientIdentity::Method::client_secret_basic;
  identity.secret = std::make_shared<Secret>(lugh::byte_span("s1"));
  auto oauth = client(identity);
  https.answer(token_url(), 200, {{"access_token", "at"}, {"token_type", "Bearer"}, {"expires_in", 300}, {"scope", "lir:sub:a openid  profile"}});
  const auto got =
      wait<TokenSet>([&](auto done) { oauth.client_credentials({"lir:sub:a", "openid", "profile"}, std::chrono::seconds(5), io.get_executor(), done); });
  ASSERT_TRUE(got.ok()) << got.message;
  EXPECT_EQ(got.value.scopes, (std::vector<std::string>{"lir:sub:a", "openid", "profile"}));
}

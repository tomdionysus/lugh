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

using namespace lugh::client;
using dannan::identity::Secret;
using Fields = std::map<std::string, std::string>;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kIssuer = "https://lugh.example";
constexpr const char* kRedirect = "https://app.example/back";

Fields fields_of(std::string_view text) {
  Fields out;
  while (!text.empty()) {
    const auto amp = text.find('&');
    const auto pair = text.substr(0, amp);
    const auto equals = pair.find('=');
    out[dannan::encoding::percent_decode(pair.substr(0, equals), dannan::encoding::Decoding::form)] =
        dannan::encoding::percent_decode(pair.substr(equals + 1), dannan::encoding::Decoding::form);
    if (amp == std::string_view::npos) break;
    text.remove_prefix(amp + 1);
  }
  return out;
}

std::string text_of(const Secret& secret) { return std::string(secret.reveal().begin(), secret.reveal().end()); }

// An HTTPS that keeps each request and answers from a table, on the caller's executor.
class RecordingHttps final : public Https {
 public:
  void send(HttpsRequest request, lugh::Deadline, lugh::Executor executor, lugh::Done<lugh::Outcome<HttpsResponse>> done) override {
    auto answer = lugh::Outcome<HttpsResponse>::failure(lugh::Fault::failed, "the connection failed");
    if (auto queue = queued.find(request.url); queue != queued.end() && !queue->second.empty()) {
      answer = queue->second.front();
      queue->second.pop_front();
    } else if (const auto found = answers.find(request.url); found != answers.end()) {
      answer = found->second;
    }
    sent.push_back(std::move(request));
    boost::asio::post(executor, [done = std::move(done), answer = std::move(answer)] { done(answer); });
  }

  void answer(const std::string& url, unsigned status, const boost::json::object& body) {
    HttpsResponse response;
    response.status = status;
    response.content_type = "application/json";
    response.body = boost::json::serialize(body);
    answers[url] = lugh::Outcome<HttpsResponse>::success(std::move(response));
  }

  // The next answer for `url`, before the table's.
  void queue(const std::string& url, unsigned status, const boost::json::object& body) {
    HttpsResponse response;
    response.status = status;
    response.content_type = "application/json";
    response.body = boost::json::serialize(body);
    queued[url].push_back(lugh::Outcome<HttpsResponse>::success(std::move(response)));
  }

  std::size_t sent_to(const std::string& url) const {
    std::size_t count = 0;
    for (const auto& one : sent) count += one.url == url ? 1 : 0;
    return count;
  }

  std::string header(std::size_t index, const std::string& name) const {
    for (const auto& [key, value] : sent.at(index).headers) {
      if (key == name) return value;
    }
    return {};
  }

  std::map<std::string, lugh::Outcome<HttpsResponse>> answers;
  std::map<std::string, std::deque<lugh::Outcome<HttpsResponse>>> queued;
  std::vector<HttpsRequest> sent;
};

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
          {"jwks_uri", std::string(kIssuer) + "/oauth2/jwks"}};
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

  std::string token_url() const { return std::string(kIssuer) + "/oauth2/token"; }

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

  ASSERT_EQ(https.sent.size(), 1u);
  EXPECT_EQ(https.sent[0].method, "POST");
  EXPECT_EQ(https.sent[0].content_type, "application/x-www-form-urlencoded");
  const auto fields = fields_of(https.sent[0].body);
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

  https.answers.clear();
  EXPECT_EQ(redeem(oauth, request).fault, lugh::Fault::failed);
  https.answer(token_url(), 200, {{"token_type", "Bearer"}});
  EXPECT_EQ(redeem(oauth, request).message, "the token endpoint's answer has no access_token");
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
  for (const auto& sent : https.sent) {
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
  const auto fields = fields_of(https.sent[0].body);
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
  const auto fields = fields_of(https.sent[0].body);
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
  const auto sent = fields_of(https.sent[0].body);
  EXPECT_EQ(https.sent[0].url, par);
  EXPECT_EQ(sent.at("client_id"), "app1");
  EXPECT_EQ(sent.at("state"), pushed.value.state);
  EXPECT_EQ(sent.at("nonce"), pushed.value.nonce);
  EXPECT_EQ(sent.at("code_challenge_method"), "S256");
  EXPECT_EQ(std::count(https.sent[0].body.begin(), https.sent[0].body.end(), '&') + 1, static_cast<long>(sent.size()));

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
  const auto fields = fields_of(https.sent[0].body);
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
  const auto fields = fields_of(https.sent.back().body);
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

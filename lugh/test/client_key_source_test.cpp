//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh::client::HttpsKeySource (TODO/2026-11-14-p10-plan.md, P10.2): each trusted issuer's
// discovery document (OpenID Connect Discovery 1.0, sections 4 and 4.3: its issuer the one asked
// for, an https jwks_uri), then its JWKS into the verifier; fetched at start, on the schedule, and
// when a token names a kid the keys lack, at most once a gap; a failure keeps the keys and backs
// off, doubling to a ceiling; each issuer's state visible; refresh_now() the operator's action;
// stop() ends the schedule. Time is stepped.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <map>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/jose.h"
#include "lugh/client/key_source.h"

using namespace lugh::client;
using std::chrono::seconds;
using State = HttpsKeySource::State;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kSiteA = "https://lugh.site-a.example";
constexpr const char* kSiteB = "https://lugh.site-b.example";

// An HTTPS that answers from a table, on the caller's executor, never inline.
class FakeHttps final : public Https {
 public:
  void send(HttpsRequest request, lugh::Deadline, lugh::Executor executor, lugh::Done<lugh::Outcome<HttpsResponse>> done) override {
    ++asked[request.url];
    auto answer = lugh::Outcome<HttpsResponse>::failure(lugh::Fault::failed, "the connection failed");
    if (const auto found = answers.find(request.url); found != answers.end()) answer = found->second;
    boost::asio::post(executor, [done = std::move(done), answer = std::move(answer)] { done(answer); });
  }

  void answer(const std::string& url, unsigned status, const boost::json::value& body) {
    HttpsResponse response;
    response.status = status;
    response.content_type = "application/json";
    response.body = boost::json::serialize(body);
    answers[url] = lugh::Outcome<HttpsResponse>::success(std::move(response));
  }

  void fail(const std::string& url) { answers.erase(url); }

  std::map<std::string, lugh::Outcome<HttpsResponse>> answers;
  std::map<std::string, int> asked;
};

struct Site {
  Site(std::string name, std::string key_id) : issuer(std::move(name)), kid(std::move(key_id)), key(SigningKey::generate(SigningAlgorithm::es256)) {}

  boost::json::object jwks() const {
    boost::json::array keys;
    keys.push_back(*public_jwk({kid, SigningAlgorithm::es256, key.public_key()}));
    return {{"keys", keys}};
  }

  std::string token() const {
    return jws_sign(key, kid, "at+jwt", {{"iss", issuer}, {"sub", "u1"}, {"aud", "lir"}, {"client_id", "app1"}, {"exp", kNow + 300}, {"jti", "j1"}});
  }

  std::string discovery_url() const { return issuer + "/.well-known/openid-configuration"; }
  std::string jwks_url() const { return issuer + "/jwks"; }

  std::string issuer;
  std::string kid;
  SigningKey key;
};

class KeySourceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    for (const auto* site : {&a, &b}) serve(*site);
  }

  void TearDown() override {
    if (source) source->stop();
    settle();
  }

  void serve(const Site& site) {
    https.answer(site.discovery_url(), 200, boost::json::object{{"issuer", site.issuer}, {"jwks_uri", site.jwks_url()}});
    https.answer(site.jwks_url(), 200, site.jwks());
  }

  void start() {
    source = HttpsKeySource::make(verifier, https, io.get_executor(), time, settings);
    source->start();
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

  HttpsKeySource::IssuerStatus status_of(const std::string& issuer) const {
    for (const auto& one : source->status()) {
      if (one.issuer == issuer) return one;
    }
    return {};
  }

  bool fresh(const Site& site) const { return status_of(site.issuer).state == State::fresh; }

  boost::asio::io_context io;
  dannan::test::SteppedTime time;
  dannan::test::SteppedWall wall{kNow * 1000};
  Site a{kSiteA, "a1"};
  Site b{kSiteB, "b1"};
  Verifier verifier{{kSiteA, kSiteB}, wall};
  FakeHttps https;
  HttpsKeySource::Settings settings;
  std::shared_ptr<HttpsKeySource> source;
};

}  // namespace

TEST_F(KeySourceTest, AtStartEachIssuersKeysAreFetched) {
  EXPECT_EQ(std::get<std::string>(verifier.verify_access(a.token())), "no keys yet for its issuer");
  start();
  ASSERT_TRUE(pump([&] { return fresh(a) && fresh(b); }));
  EXPECT_EQ(status_of(kSiteA).keys, 1u);
  EXPECT_TRUE(status_of(kSiteA).last_error.empty());
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(a.token())));
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(b.token())));
  EXPECT_EQ(https.asked[a.discovery_url()], 1);
  EXPECT_EQ(https.asked[a.jwks_url()], 1);
}

TEST_F(KeySourceTest, TheDiscoveryDocumentMustNameItsIssuerAndAnHttpsJwksUri) {
  https.answer(a.discovery_url(), 200, boost::json::object{{"issuer", "https://elsewhere.example"}, {"jwks_uri", a.jwks_url()}});
  https.answer(b.discovery_url(), 200, boost::json::object{{"issuer", kSiteB}, {"jwks_uri", "http://lugh.site-b.example/jwks"}});
  start();
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures > 0 && status_of(kSiteB).failures > 0; }));
  EXPECT_EQ(status_of(kSiteA).state, State::waiting);
  EXPECT_EQ(status_of(kSiteA).last_error, "the discovery document names another issuer");
  EXPECT_EQ(status_of(kSiteB).last_error, "the discovery document has no https jwks_uri");
  EXPECT_EQ(https.asked[a.jwks_url()], 0);
  EXPECT_EQ(std::get<std::string>(verifier.verify_access(a.token())), "no keys yet for its issuer");
}

TEST_F(KeySourceTest, AFailureKeepsTheKeysAndBacksOffDoubling) {
  start();
  ASSERT_TRUE(pump([&] { return fresh(a); }));
  https.answer(a.jwks_url(), 500, boost::json::object{});

  // The schedule comes round; the fetch fails; the keys held still check tokens.
  time.advance(settings.refresh);
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 1; }));
  EXPECT_EQ(status_of(kSiteA).state, State::stale);
  EXPECT_EQ(status_of(kSiteA).last_error, "the JWKS answered 500");
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(a.token())));

  // Tried again after the first backoff, not before; then after twice that.
  time.advance(settings.first_backoff - seconds(1));
  settle();
  EXPECT_EQ(https.asked[a.jwks_url()], 2);
  time.advance(seconds(1));
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 2; }));
  EXPECT_EQ(https.asked[a.jwks_url()], 3);
  time.advance(settings.first_backoff * 2 - seconds(1));
  settle();
  EXPECT_EQ(https.asked[a.jwks_url()], 3);
  time.advance(seconds(1));
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 3; }));

  // The issuer answers again: fresh, and the failures forgotten.
  serve(a);
  time.advance(settings.first_backoff * 4);
  ASSERT_TRUE(pump([&] { return fresh(a); }));
  EXPECT_EQ(status_of(kSiteA).failures, 0u);
}

TEST_F(KeySourceTest, TheBackoffStopsAtItsCeiling) {
  settings.first_backoff = seconds(100);
  settings.most_backoff = seconds(150);
  https.fail(a.jwks_url());
  start();
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 1; }));
  time.advance(seconds(100));
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 2; }));
  // Not 200 s: the ceiling.
  time.advance(seconds(150));
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 3; }));
}

TEST_F(KeySourceTest, AnUnknownKidPromptsAFetchAtMostOnceAGap) {
  start();
  ASSERT_TRUE(pump([&] { return fresh(a); }));
  ASSERT_EQ(https.asked[a.jwks_url()], 1);

  // Site A rotates: a token under the new kid is refused, and prompts a fetch after the gap.
  const Site rotated{kSiteA, "a2"};
  serve(rotated);
  time.advance(settings.missing_gap);
  EXPECT_EQ(std::get<std::string>(verifier.verify_access(rotated.token())), "no key with its kid");
  ASSERT_TRUE(pump([&] { return https.asked[a.jwks_url()] == 2 && fresh(a); }));
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(rotated.token())));

  // A stream of forged kids within the gap costs nothing more.
  const Site forged{kSiteA, "zz"};
  for (int i = 0; i < 10; ++i) verifier.verify_access(forged.token());
  settle();
  EXPECT_EQ(https.asked[a.jwks_url()], 2);
  time.advance(settings.missing_gap);
  verifier.verify_access(forged.token());
  ASSERT_TRUE(pump([&] { return https.asked[a.jwks_url()] == 3; }));
}

TEST_F(KeySourceTest, RefreshNowIsTheOperatorsAction) {
  https.fail(a.jwks_url());
  start();
  ASSERT_TRUE(pump([&] { return status_of(kSiteA).failures == 1; }));
  serve(a);
  // Within the backoff, the operator asks: fetched at once.
  source->refresh_now();
  ASSERT_TRUE(pump([&] { return fresh(a); }));
  EXPECT_EQ(https.asked[a.jwks_url()], 2);
}

TEST_F(KeySourceTest, StopEndsTheSchedule) {
  start();
  ASSERT_TRUE(pump([&] { return fresh(a) && fresh(b); }));
  source->stop();
  time.advance(settings.refresh * 2);
  settle();
  EXPECT_EQ(https.asked[a.jwks_url()], 1);
  // The keys stay with the verifier.
  EXPECT_TRUE(std::holds_alternative<AccessToken>(verifier.verify_access(a.token())));
  // And refused tokens no longer prompt anything.
  const Site forged{kSiteA, "zz"};
  verifier.verify_access(forged.token());
  settle();
  EXPECT_EQ(https.asked[a.jwks_url()], 1);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What a service that trusts Lugh needs whole (the stack's placement plan, items 50, 53, 54
// and S10, asked by Louhi and Lir): discover(), bearer_token(), RelyingParty, TokenSource
// with failover across issuers, and the fake HTTPS that holds a request until the test
// answers it. Time is stepped.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/jose.h"
#include "lugh/client/relying_party.h"
#include "lugh/client/testing.h"
#include "lugh/core/secret.h"

using namespace lugh::client;
using std::chrono::seconds;
namespace fake = lugh::client::testing;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kSiteA = "https://lugh.site-a.example";
constexpr const char* kSiteB = "https://lugh.site-b.example";

std::string discovery_url(const std::string& issuer) { return issuer + "/.well-known/openid-configuration"; }
std::string token_url(const std::string& issuer) { return issuer + "/oauth/token"; }
std::string jwks_url(const std::string& issuer) { return issuer + "/jwks"; }

boost::json::object discovery_of(const std::string& issuer) {
  return {{"issuer", issuer}, {"authorization_endpoint", issuer + "/oauth/authorize"}, {"token_endpoint", token_url(issuer)}, {"jwks_uri", jwks_url(issuer)}};
}

boost::json::object token_answer(const std::string& token, std::uint32_t life) {
  return {{"access_token", token}, {"token_type", "Bearer"}, {"expires_in", life}};
}

class RelyingPartyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    for (const auto* issuer : {kSiteA, kSiteB}) https.answer(discovery_url(issuer), 200, discovery_of(issuer));
  }

  void TearDown() override {
    if (source) source->stop();
    settle();
  }

  template <typename Predicate>
  bool pump(Predicate done) {
    for (int i = 0; i < 400 && !done(); ++i) {
      io.restart();
      io.run_for(std::chrono::milliseconds(5));
    }
    return done();
  }

  void settle() {
    for (int i = 0; i < 20; ++i) {
      io.restart();
      io.run_for(std::chrono::milliseconds(5));
    }
  }

  // Time moved on, and the io context given a chance to act on it.
  void advance(std::chrono::milliseconds by) {
    time.advance(by);
    wall.advance(by);
    settle();
  }

  TokenSource::Settings credentials(std::vector<std::string> issuers) {
    TokenSource::Settings out;
    out.issuers = std::move(issuers);
    out.identity.client_id = "louhi-node";
    out.identity.method = ClientIdentity::Method::client_secret_basic;
    out.identity.secret = std::make_shared<const dannan::identity::Secret>(lugh::text_secret("s3cret"));
    return out;
  }

  boost::asio::io_context io;
  dannan::test::SteppedTime time;
  dannan::test::SteppedWall wall{kNow * 1000};
  fake::FakeHttps https;
  std::shared_ptr<TokenSource> source;
};

}  // namespace

TEST(BearerToken, TheSchemeInAnyCaseThenATokenOfB64tokenCharacters) {
  EXPECT_EQ(bearer_token("Bearer abc.DEF-ghi_~+/=="), "abc.DEF-ghi_~+/==");
  EXPECT_EQ(bearer_token("bearer abc"), "abc");
  EXPECT_EQ(bearer_token("BEARER   abc"), "abc");
  EXPECT_FALSE(bearer_token("Basic abc"));
  EXPECT_FALSE(bearer_token("DPoP abc"));
  EXPECT_FALSE(bearer_token("Bearerabc"));
  EXPECT_FALSE(bearer_token("Bearer "));
  EXPECT_FALSE(bearer_token("Bearer a b"));
  EXPECT_FALSE(bearer_token("Bearer a=b"));
  EXPECT_FALSE(bearer_token("Bearer abc "));
  EXPECT_FALSE(bearer_token(""));
  EXPECT_FALSE(bearer_token("Bearer " + std::string(kMostAuthorizationBytes, 'a')));
}

TEST_F(RelyingPartyTest, DiscoverReadsTheIssuersOwnEndpoints) {
  std::optional<lugh::Outcome<Endpoints>> found;
  discover(https, kSiteA, seconds(5), io.get_executor(), [&](lugh::Outcome<Endpoints> got) { found = std::move(got); });
  ASSERT_TRUE(pump([&] { return found.has_value(); }));
  ASSERT_TRUE(found->ok()) << found->message;
  EXPECT_EQ(found->value.token, token_url(kSiteA));
}

TEST_F(RelyingPartyTest, DiscoverRefusesAnotherIssuersDocumentAndFailsWhenUnreachable) {
  https.answer(discovery_url(kSiteA), 200, discovery_of(kSiteB));
  std::optional<lugh::Outcome<Endpoints>> other;
  discover(https, kSiteA, seconds(5), io.get_executor(), [&](lugh::Outcome<Endpoints> got) { other = std::move(got); });
  std::optional<lugh::Outcome<Endpoints>> unreachable;
  discover(https, "https://nowhere.example", seconds(5), io.get_executor(), [&](lugh::Outcome<Endpoints> got) { unreachable = std::move(got); });
  ASSERT_TRUE(pump([&] { return other && unreachable; }));
  EXPECT_EQ(other->fault, lugh::Fault::refused);
  EXPECT_EQ(unreachable->fault, lugh::Fault::failed);
}

TEST_F(RelyingPartyTest, ARelyingPartyVerifiesTokensForItsAudienceOnly) {
  const auto key = dannan::identity::SigningKey::generate(dannan::identity::SigningAlgorithm::es256);
  https.answer(jwks_url(kSiteA), 200, fake::jwks(key, "a1"));
  RelyingParty::Settings settings;
  settings.issuers = {kSiteA};
  settings.audience = "louhi";
  RelyingParty party(https, io.get_executor(), settings, time, wall);
  party.start();
  ASSERT_TRUE(pump([&] { return !party.status().empty() && party.status()[0].state == HttpsKeySource::State::fresh; }));

  const auto token = [&](const std::string& audience) {
    return fake::sign_access_token(
        key, "a1", {{"iss", kSiteA}, {"sub", "u1"}, {"aud", audience}, {"client_id", "app1"}, {"exp", kNow + 300}, {"iat", kNow}, {"jti", "j1"}});
  };
  EXPECT_TRUE(std::holds_alternative<AccessToken>(party.verify(token("louhi"))));
  EXPECT_TRUE(std::holds_alternative<AccessToken>(party.verify_header("Bearer " + token("louhi"))));
  EXPECT_TRUE(std::holds_alternative<std::string>(party.verify(token("lir"))));
  EXPECT_TRUE(std::holds_alternative<std::string>(party.verify_header("Basic " + token("louhi"))));
  party.stop();
  settle();
}

TEST_F(RelyingPartyTest, ARelyingPartyNeedsIssuersAndAnAudience) {
  RelyingParty::Settings settings;
  settings.audience = "louhi";
  EXPECT_THROW(RelyingParty(https, io.get_executor(), settings, time, wall), std::invalid_argument);
  settings.issuers = {kSiteA};
  settings.audience.clear();
  EXPECT_THROW(RelyingParty(https, io.get_executor(), settings, time, wall), std::invalid_argument);
}

TEST_F(RelyingPartyTest, ATokenSourceFetchesAtStartAndAgainAtTwoThirdsOfItsLife) {
  https.queue(token_url(kSiteA), 200, token_answer("first", 300));
  https.queue(token_url(kSiteA), 200, token_answer("second", 300));
  source = TokenSource::make(https, io.get_executor(), credentials({kSiteA}), time, wall);
  EXPECT_FALSE(source->current());
  source->start();
  ASSERT_TRUE(pump([&] { return source->current() == "first"; }));
  EXPECT_EQ(https.header(1, "Authorization").rfind("Basic ", 0), 0U);

  advance(seconds(199));
  EXPECT_EQ(source->current(), "first");
  advance(seconds(2));
  ASSERT_TRUE(pump([&] { return source->current() == "second"; }));
  EXPECT_EQ(https.sent_to(discovery_url(kSiteA)), 1U);
}

// Any one Lugh down is not the service's problem: the next issuer is asked, and the token held
// is kept meanwhile.
TEST_F(RelyingPartyTest, ATokenSourceFailsOverToTheNextIssuer) {
  https.queue(token_url(kSiteA), 200, token_answer("from-a", 30));
  https.queue(token_url(kSiteB), 200, token_answer("from-b", 300));
  source = TokenSource::make(https, io.get_executor(), credentials({kSiteA, kSiteB}), time, wall);
  source->start();
  ASSERT_TRUE(pump([&] { return source->current() == "from-a"; }));
  EXPECT_EQ(source->status().issuer, kSiteA);

  // Site A's token endpoint is gone: the refresh at 20 s fails there and keeps the token.
  advance(seconds(20));
  ASSERT_TRUE(pump([&] { return source->status().failures == 1; }));
  EXPECT_EQ(source->current(), "from-a");
  // After the first back-off, site B is asked.
  advance(seconds(5));
  ASSERT_TRUE(pump([&] { return source->current() == "from-b"; }));
  EXPECT_EQ(source->status().issuer, kSiteB);
  EXPECT_EQ(source->status().failures, 0U);
}

TEST_F(RelyingPartyTest, ATokenSourceBacksOffDoublingAndNeverParks) {
  source = TokenSource::make(https, io.get_executor(), credentials({kSiteA}), time, wall);
  source->start();
  ASSERT_TRUE(pump([&] { return source->status().failures == 1; }));
  for (std::uint32_t failures = 2; failures <= 10; ++failures) {
    advance(seconds(300));
    ASSERT_TRUE(pump([&] { return source->status().failures == failures; })) << failures;
  }
  https.queue(token_url(kSiteA), 200, token_answer("at-last", 300));
  advance(seconds(300));
  ASSERT_TRUE(pump([&] { return source->current() == "at-last"; }));
}

TEST_F(RelyingPartyTest, NothingIsAskedAfterStopAndALateAnswerIsDropped) {
  https.hold(token_url(kSiteA));
  source = TokenSource::make(https, io.get_executor(), credentials({kSiteA}), time, wall);
  source->start();
  ASSERT_TRUE(pump([&] { return https.held() == 1; }));
  source->stop();
  settle();
  https.release(lugh::Outcome<fake::FakeHttps::Response>::success(fake::FakeHttps::json(200, token_answer("late", 300))));
  settle();
  EXPECT_FALSE(source->current());
  advance(seconds(600));
  EXPECT_EQ(https.sent_to(token_url(kSiteA)), 1U);
}

TEST_F(RelyingPartyTest, ATokenSourceRefusesAnIdentityThatCannotSignIn) {
  auto settings = credentials({kSiteA});
  settings.identity.method = ClientIdentity::Method::none;
  EXPECT_THROW(TokenSource::make(https, io.get_executor(), settings, time, wall), std::invalid_argument);
  EXPECT_THROW(TokenSource::make(https, io.get_executor(), credentials({}), time, wall), std::invalid_argument);
}

TEST_F(RelyingPartyTest, PrivateKeyJwtNeedsItsKeyAndKid) {
  auto settings = credentials({kSiteA});
  settings.identity.method = ClientIdentity::Method::private_key_jwt;
  settings.identity.secret.reset();
  EXPECT_THROW(TokenSource::make(https, io.get_executor(), settings, time, wall), std::invalid_argument);
  settings.identity.key = std::make_shared<const lugh::client::SigningKey>(lugh::client::SigningKey::generate(lugh::client::SigningAlgorithm::es256));
  EXPECT_THROW(TokenSource::make(https, io.get_executor(), settings, time, wall), std::invalid_argument) << "a key without its kid";
}

// Given an io_context rather than an Https, a relying party makes and owns its own client, and
// fetches nothing until it is started.
TEST_F(RelyingPartyTest, ARelyingPartyMayOwnItsHttpsClient) {
  RelyingParty::Settings settings;
  settings.issuers = {kSiteA};
  settings.audience = "louhi";
  RelyingParty party(io, settings, time, wall);
  const auto status = party.status();
  ASSERT_EQ(status.size(), 1u);
  EXPECT_EQ(status[0].issuer, kSiteA);
  settle();
  EXPECT_TRUE(https.sent().empty());
}

// A held URL answers once it is let go: what is sent to it from then on is answered at once.
TEST_F(RelyingPartyTest, AHeldUrlLetGoAnswersAgain) {
  https.answer(std::string(kSiteA) + "/x", 200, {{"ok", true}});
  https.hold(std::string(kSiteA) + "/x");
  https.let_go(std::string(kSiteA) + "/x");
  lugh::client::HttpsRequest request;
  request.url = std::string(kSiteA) + "/x";
  std::optional<lugh::Outcome<lugh::client::HttpsResponse>> got;
  https.send(request, std::chrono::seconds(5), io.get_executor(), [&](lugh::Outcome<lugh::client::HttpsResponse> answer) { got = std::move(answer); });
  settle();
  ASSERT_TRUE(got);
  EXPECT_TRUE(got->ok());
}

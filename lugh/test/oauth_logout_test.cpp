//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/client/jose.h"
#include "lugh/core/encoding.h"
#include "lugh/test/fixtures/signin_rig.h"

using lugh::http::verb;

namespace {

constexpr const char* kPassword = "correct horse battery";
constexpr const char* kRedirect = "https://client.example.com/cb";
constexpr const char* kAfter = "https://client.example.com/bye";
constexpr const char* kBackchannel = "https://client.example.com/backchannel";
constexpr const char* kVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
constexpr const char* kChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

std::string encoded(const std::string& text) { return dannan::encoding::percent_encode(text, dannan::encoding::PercentSet::unreserved()); }

std::string query_value(const std::string& uri, const std::string& name) {
  const auto at = uri.find(name + "=");
  if (at == std::string::npos) return {};
  const auto from = at + name.size() + 1;
  return dannan::encoding::percent_decode(uri.substr(from, uri.find('&', from) - from), dannan::encoding::Decoding::form);
}

class LogoutTest : public ::testing::Test {
 protected:
  void SetUp() override {
    alice = rig.enrolled("alice");
    staff = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
              rig.directory->create_group(rig.admin, "staff", "", kTestDeadline, executor, done);
            }).value;
    ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                  rig.directory->add_member(rig.admin, staff.id, alice.id, kTestDeadline, executor, done);
                }).ok());
    client = register_app(kBackchannel);
    id_token = sign_in_and_get_id_token(client);
  }

  struct Client {
    std::string id;
    std::string secret;
  };

  Client register_app(const std::string& backchannel) {
    lugh::apps::App draft;
    draft.name = "Client";
    draft.kind = lugh::apps::Kind::web;
    draft.auth = lugh::apps::ClientAuth::client_secret_basic;
    draft.grants = lugh::apps::kAuthorizationCode;
    draft.redirect_uris = {kRedirect};
    draft.post_logout_uris = {kAfter};
    draft.backchannel_logout_uri = backchannel;
    draft.scopes = {"openid"};
    draft.first_party = true;
    auto made = wait_for<lugh::Outcome<lugh::apps::Apps::Made>>(
        [&](lugh::Executor executor, auto done) { rig.apps->create(rig.admin, draft, kTestDeadline, executor, done); });
    EXPECT_TRUE(made.ok()) << made.message;
    const auto id = made.value.app.client_id;
    EXPECT_TRUE(wait_for<lugh::Outcome<lugh::apps::App>>([&](lugh::Executor executor, auto done) {
                  rig.apps->access_set(rig.admin, id, staff.id, true, kTestDeadline, executor, done);
                }).ok());
    return {id, std::string(lugh::secret_text(*made.value.secret))};
  }

  std::string authorize_target(const std::string& client_id) {
    return "/oauth2/authorize?response_type=code&client_id=" + client_id + "&redirect_uri=" + encoded(kRedirect) +
           "&scope=openid&state=st8&nonce=n0nce&code_challenge=" + kChallenge + "&code_challenge_method=S256";
  }

  // Signs in if there is no session yet, and answers the ID token the client gets.
  std::string sign_in_and_get_id_token(const Client& app) {
    auto first = rig.get(authorize_target(app.id));
    std::string back = first.location();
    if (back.rfind("/signin", 0) == 0) {
      const auto form = rig.get(back);
      const auto resume = form.between("name=\"continue\" value=\"", "\"");
      rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}, {"continue", resume}});
      const auto factor = rig.get("/signin/factor");
      rig.advance(std::chrono::seconds(30));
      const auto done = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
      back = rig.get(done.location()).location();
    }
    const auto text = app.id + ":" + app.secret;
    auto basic = lugh::encoding::base64url(lugh::byte_span(text));
    for (auto& c : basic) c = c == '-' ? '+' : (c == '_' ? '/' : c);
    while (basic.size() % 4) basic.push_back('=');
    const auto tokens =
        rig.request(verb::post, "/oauth2/token",
                    {{"grant_type", "authorization_code"}, {"code", query_value(back, "code")}, {"redirect_uri", kRedirect}, {"code_verifier", kVerifier}},
                    {{"Authorization", "Basic " + basic}});
    EXPECT_EQ(tokens.status, 200u) << tokens.body;
    access_token = std::string(boost::json::parse(tokens.body).at("access_token").as_string());
    return std::string(boost::json::parse(tokens.body).at("id_token").as_string());
  }

  bool signed_in() { return rig.get("/api/v1/me").status == 200u; }

  std::string logout_target(const std::string& hint, const std::string& after = "", const std::string& state = "") {
    std::string target = "/oauth2/logout?id_token_hint=" + hint;
    if (!after.empty()) target += "&post_logout_redirect_uri=" + encoded(after);
    if (!state.empty()) target += "&state=" + state;
    return target;
  }

  void deliver() {
    ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { rig.backchannel->deliver_due(kTestDeadline, executor, done); }).ok);
  }

  SigninRig rig;
  lugh::directory::User alice;
  lugh::directory::Group staff;
  Client client;
  std::string id_token;
  std::string access_token;
};

}  // namespace

// RP-Initiated Logout section 2: a hint for this session ends it, and back to the registered URI.
TEST_F(LogoutTest, AHintForThisSessionEndsItAndGoesBack) {
  ASSERT_TRUE(signed_in());
  const auto answer = rig.get(logout_target(id_token, kAfter, "st9"));
  ASSERT_EQ(answer.status, 303u) << answer.body;
  EXPECT_EQ(answer.location(), std::string(kAfter) + "?state=st9");
  EXPECT_FALSE(signed_in());
  EXPECT_EQ(rig.jar.count("__Host-lugh_session"), 0u);
}

TEST_F(LogoutTest, AHintWithNoUriEndsOnAPageOfLughs) {
  const auto answer = rig.get(logout_target(id_token));
  EXPECT_EQ(answer.status, 200u);
  EXPECT_TRUE(answer.says("You are signed out"));
  EXPECT_FALSE(signed_in());
}

// Section 2: an expired ID token is still a good hint.
TEST_F(LogoutTest, AnExpiredHintStillWorks) {
  rig.advance(std::chrono::hours(2));
  EXPECT_EQ(rig.get(logout_target(id_token, kAfter)).location(), kAfter);
  EXPECT_FALSE(signed_in());
}

// Section 3: only a URI registered, exactly, is ever followed.
TEST_F(LogoutTest, AnUnregisteredUriIsRefusedAndNotFollowed) {
  for (const std::string after : {"https://evil.example.com/", "https://client.example.com/bye/", "https://client.example.com/bye?x=1"}) {
    const auto answer = rig.get(logout_target(id_token, after));
    EXPECT_EQ(answer.status, 400u) << after;
    EXPECT_TRUE(answer.location().empty()) << after;
  }
  EXPECT_TRUE(signed_in());
}

TEST_F(LogoutTest, AUriNeedsToKnowWhoseItIs) {
  EXPECT_EQ(rig.get("/oauth2/logout?post_logout_redirect_uri=" + encoded(kAfter)).status, 400u);
  EXPECT_TRUE(signed_in());
}

TEST_F(LogoutTest, AHintThatIsNotOneOfLughsIsRefused) {
  auto tampered = id_token;
  tampered[tampered.size() - 2] = tampered[tampered.size() - 2] == 'A' ? 'B' : 'A';
  EXPECT_EQ(rig.get(logout_target(tampered, kAfter)).status, 400u);
  EXPECT_EQ(rig.get(logout_target("not-a-token", kAfter)).status, 400u);
  EXPECT_TRUE(signed_in());
}

// Lugh's own tokens of other kinds, however good, are not ID tokens.
TEST_F(LogoutTest, OtherTokensAreNotHints) {
  EXPECT_EQ(rig.get(logout_target(access_token)).status, 400u);
  const auto logout_token = rig.issuer->logout_token(client.id, alice.id, "sid");
  ASSERT_TRUE(logout_token);
  EXPECT_EQ(rig.get(logout_target(*logout_token)).status, 400u);
  EXPECT_TRUE(signed_in());
}

// Section 2: client_id, when given with a hint, must be the one it was issued to.
TEST_F(LogoutTest, AClientIdThatDisagreesIsRefused) {
  EXPECT_EQ(rig.get(logout_target(id_token) + "&client_id=someone-else").status, 400u);
  EXPECT_TRUE(signed_in());
}

// No hint: nothing ends until the person says so, on a page only Lugh can have served.
TEST_F(LogoutTest, WithoutAHintThePersonIsAsked) {
  const auto asked = rig.get("/oauth2/logout?client_id=" + client.id + "&post_logout_redirect_uri=" + encoded(kAfter) + "&state=st9");
  ASSERT_EQ(asked.status, 200u) << asked.body;
  EXPECT_TRUE(asked.says("Sign out?"));
  EXPECT_TRUE(signed_in());

  EXPECT_EQ(rig.post("/oauth2/logout", {{"csrf", "forged"}, {"client_id", client.id}, {"post_logout_redirect_uri", kAfter}}).status, 403u);
  EXPECT_TRUE(signed_in());

  const auto answered = rig.post("/oauth2/logout", {{"csrf", asked.csrf()}, {"client_id", client.id}, {"post_logout_redirect_uri", kAfter}, {"state", "st9"}});
  ASSERT_EQ(answered.status, 200u) << answered.body;
  // Leaving from a form's answer is a page: form-action would stop a redirect.
  EXPECT_TRUE(answered.header("Location").empty());
  EXPECT_TRUE(answered.says("content=\"0; url=https://client.example.com/bye?state=st9\""));
  EXPECT_TRUE(answered.says("href=\"https://client.example.com/bye?state=st9\""));
  EXPECT_FALSE(signed_in());
}

// A token in a URL is no answer to the question.
TEST_F(LogoutTest, ATokenInTheUrlCountsForNothing) {
  const auto token = rig.get("/oauth2/logout").csrf();
  ASSERT_FALSE(token.empty());
  EXPECT_TRUE(rig.get("/oauth2/logout?csrf=" + token).says("Sign out?"));
  EXPECT_TRUE(signed_in());
}

// A hint from an earlier session of the same person does not end this one unasked.
TEST_F(LogoutTest, AHintForAnotherSessionAsks) {
  rig.jar.clear();
  const auto form = rig.get("/signin");
  rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}});
  const auto factor = rig.get("/signin/factor");
  rig.advance(std::chrono::seconds(30));
  rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
  const auto answer = rig.get(logout_target(id_token, kAfter));
  EXPECT_EQ(answer.status, 200u);
  EXPECT_TRUE(answer.says("Sign out?"));
  EXPECT_TRUE(signed_in());
}

// Nothing to end: still back to the application.
TEST_F(LogoutTest, AlreadySignedOutStillGoesBack) {
  rig.jar.clear();
  EXPECT_EQ(rig.get(logout_target(id_token, kAfter, "st9")).location(), std::string(kAfter) + "?state=st9");
}

// Back-Channel Logout section 2.4: what a logout token says.
TEST_F(LogoutTest, ALogoutTokenSaysWhatTheSpecificationSays) {
  ASSERT_TRUE(signed_in());
  const auto sid = rig.sessions->of_user(alice.id).front().sid;
  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  EXPECT_EQ(rig.backchannel->waiting(), 1u);
  deliver();
  ASSERT_EQ(rig.outbound->posts.size(), 1u);
  const auto& post = rig.outbound->posts.front();
  EXPECT_EQ(post.url, kBackchannel);
  ASSERT_EQ(post.body.rfind("logout_token=", 0), 0u);

  const auto token = lugh::tokens::jws_parse(post.body.substr(13));
  ASSERT_TRUE(token);
  EXPECT_EQ(token->typ, "logout+jwt");
  EXPECT_TRUE(lugh::tokens::jws_verify(*token, rig.keys->published()));
  const auto& claims = token->claims;
  EXPECT_EQ(claims.at("iss"), SigninRig::kIssuer);
  EXPECT_EQ(claims.at("aud"), boost::json::value(client.id));
  EXPECT_EQ(claims.at("sub"), boost::json::value(alice.id));
  EXPECT_EQ(claims.at("sid"), boost::json::value(sid));
  EXPECT_TRUE(claims.contains("jti"));
  EXPECT_LE(claims.at("exp").to_number<std::uint64_t>() - claims.at("iat").to_number<std::uint64_t>(), 120u);
  EXPECT_TRUE(claims.at("events").as_object().contains("http://schemas.openid.net/event/backchannel-logout"));
  EXPECT_FALSE(claims.contains("nonce"));

  EXPECT_EQ(rig.backchannel->waiting(), 0u);
  EXPECT_TRUE(rig.audited("logout.backchannel"));
}

// However the session ends.
TEST_F(LogoutTest, EndingASessionAnyOtherWayTellsTheApplicationsToo) {
  const auto ended = wait_for<lugh::Outcome<std::size_t>>(
      [&](lugh::Executor executor, auto done) { rig.sessions->end_user(rig.admin, alice.id, "", "the test", kTestDeadline, executor, done); });
  ASSERT_TRUE(ended.ok());
  deliver();
  EXPECT_EQ(rig.outbound->posts.size(), 1u);
}

// Every application signed in through the session that asks, each once, and no other.
TEST_F(LogoutTest, EveryApplicationThatAskedIsToldOnce) {
  const auto second = register_app("https://second.example.com/backchannel");
  const auto silent = register_app("");
  register_app("https://never-signed-in.example.com/backchannel");
  sign_in_and_get_id_token(second);
  sign_in_and_get_id_token(silent);
  sign_in_and_get_id_token(client);

  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  deliver();
  std::vector<std::string> told;
  for (const auto& post : rig.outbound->posts) told.push_back(post.url);
  std::sort(told.begin(), told.end());
  EXPECT_EQ(told, (std::vector<std::string>{kBackchannel, "https://second.example.com/backchannel"}));
  EXPECT_EQ(rig.backchannel->waiting(), 0u);
}

// A session that has told no application anything has nobody to tell.
TEST_F(LogoutTest, ASessionNoApplicationUsedTellsNobody) {
  rig.jar.clear();
  const auto form = rig.get("/signin");
  rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}});
  const auto factor = rig.get("/signin/factor");
  rig.advance(std::chrono::seconds(30));
  rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
  const auto mine = rig.jar.at("__Host-lugh_session");
  ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) { rig.sessions->end(rig.admin, mine, kTestDeadline, executor, done); }).ok());
  EXPECT_EQ(rig.backchannel->waiting(), 0u);
}

// Which applications a session has told survives the node restarting.
TEST_F(LogoutTest, TheApplicationsSurviveARestart) {
  auto again = std::make_shared<lugh::session::Sessions>(rig.store, rig.wall, rig.directory, rig.grants, rig.audit, lugh::session::Sessions::Settings{});
  ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { again->open(kTestDeadline, executor, done); }).ok);
  const auto sessions = again->of_user(alice.id);
  ASSERT_EQ(sessions.size(), 1u);
  EXPECT_EQ(sessions.front().apps, (std::vector<std::string>{client.id}));
}

// A record written before applications were kept is still read.
TEST_F(LogoutTest, ASessionRecordOfTheEarlierFormatIsRead) {
  auto session = rig.sessions->of_user(alice.id).front();
  session.apps.clear();
  const auto encoded_now = lugh::session::Sessions::encode(session);
  std::vector<unsigned char> earlier(encoded_now.begin(), encoded_now.end() - 4);
  earlier[0] = 1;
  const auto read = lugh::session::Sessions::decode(earlier);
  ASSERT_TRUE(read);
  EXPECT_EQ(read->sid, session.sid);
  EXPECT_TRUE(read->apps.empty());
  earlier[0] = 3;
  EXPECT_FALSE(lugh::session::Sessions::decode(earlier));
}

TEST_F(LogoutTest, NotingAnApplicationOnASessionEndedIsRefused) {
  const auto session = rig.sessions->of_user(alice.id).front();
  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  const auto noted =
      wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) { rig.sessions->note_app(session.key, "another", kTestDeadline, executor, done); });
  EXPECT_EQ(noted.fault, lugh::Fault::not_found);
}

// Refused or unanswered, tried again with the wait doubling; a fresh token each time.
TEST_F(LogoutTest, ARefusalIsTriedAgainWithTheWaitDoubling) {
  rig.outbound->status = 500;
  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  deliver();
  ASSERT_EQ(rig.outbound->posts.size(), 1u);

  deliver();
  EXPECT_EQ(rig.outbound->posts.size(), 1u);
  rig.advance(std::chrono::seconds(29));
  deliver();
  EXPECT_EQ(rig.outbound->posts.size(), 1u);
  rig.advance(std::chrono::seconds(1));
  rig.outbound->status = 0;
  deliver();
  ASSERT_EQ(rig.outbound->posts.size(), 2u);
  EXPECT_NE(rig.outbound->posts[0].body, rig.outbound->posts[1].body);

  rig.advance(std::chrono::seconds(59));
  deliver();
  EXPECT_EQ(rig.outbound->posts.size(), 2u);
  rig.advance(std::chrono::seconds(1));
  rig.outbound->status = 204;
  deliver();
  EXPECT_EQ(rig.outbound->posts.size(), 3u);
  EXPECT_EQ(rig.backchannel->waiting(), 0u);
  EXPECT_TRUE(rig.audited("logout.backchannel"));
}

// A redirect is not a delivery.
TEST_F(LogoutTest, ARedirectIsNotDelivered) {
  rig.outbound->status = 302;
  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  deliver();
  EXPECT_EQ(rig.backchannel->waiting(), 1u);
}

TEST_F(LogoutTest, GivenUpOnAfterAnHourAndAudited) {
  rig.outbound->status = 503;
  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  for (int i = 0; i < 400 && rig.backchannel->waiting() > 0; ++i) {
    deliver();
    rig.advance(std::chrono::seconds(30));
  }
  EXPECT_EQ(rig.backchannel->waiting(), 0u);
  EXPECT_TRUE(rig.audited("logout.backchannel.failed"));
  // At once, then 0.5, 1.5, 3.5, 7.5, 15.5 and 31.5 minutes in; the next would be past the hour.
  EXPECT_EQ(rig.outbound->posts.size(), 7u);
}

// An application removed while its logout waits is owed nothing more.
TEST_F(LogoutTest, AnApplicationRemovedIsNotTold) {
  ASSERT_EQ(rig.get(logout_target(id_token)).status, 200u);
  ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.apps->remove(rig.admin, client.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  deliver();
  EXPECT_TRUE(rig.outbound->posts.empty());
  EXPECT_EQ(rig.backchannel->waiting(), 0u);
}

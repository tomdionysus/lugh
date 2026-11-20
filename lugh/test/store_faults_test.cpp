//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// When the store fails, or refuses a write another writer won: what each part of Lugh does, and
// what it says. A read that fails is never taken for absence (lugh/store/store_calls.h); a write
// that fails changes nothing and says so; a race lost is the loser's refusal. The faults are the
// test store's, armed per table (lugh/test/fixtures/memory_store.h).

#include <gtest/gtest.h>

#include "lugh/apps/app.h"
#include "lugh/authn/enrolment_links.h"
#include "lugh/authn/factors.h"
#include "lugh/authn/passwords.h"
#include "lugh/directory/posix_numbers.h"
#include "lugh/oauth/refresh_tokens.h"
#include "lugh/test/fixtures/signin_rig.h"

using lugh::Fault;
using lugh::http::verb;
using lugh::store::StoreError;

namespace {

constexpr const char* kPassword = "correct horse battery";
constexpr const char* kRedirect = "https://client.example.com/cb";
// RFC 7636 appendix B.
constexpr const char* kVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
constexpr const char* kChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

std::string basic(const std::string& client_id, const std::string& secret) {
  const auto text = client_id + ":" + secret;
  auto encoded = lugh::encoding::base64url(lugh::byte_span(text));
  for (auto& c : encoded) c = c == '-' ? '+' : (c == '_' ? '/' : c);
  while (encoded.size() % 4) encoded.push_back('=');
  return "Basic " + encoded;
}

std::string query_value(const std::string& uri, const std::string& name) {
  const auto at = uri.find(name + "=");
  if (at == std::string::npos) return {};
  const auto from = at + name.size() + 1;
  return uri.substr(from, uri.find('&', from) - from);
}

std::string error_of(const SigninRig::Page& page) {
  const auto body = boost::json::parse(page.body);
  const auto& error = body.at("error");
  return error.is_string() ? std::string(error.as_string()) : std::string(error.at("code").as_string());
}

class StoreFaultsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    alice = rig.enrolled("alice");
    staff = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
              rig.directory->create_group(rig.admin, "staff", "", kTestDeadline, executor, done);
            }).value;
    ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                  rig.directory->add_member(rig.admin, staff.id, alice.id, kTestDeadline, executor, done);
                }).ok());
  }

  // A first-party web application with refresh tokens, allowed to staff.
  std::pair<lugh::apps::App, std::string> web_app() {
    lugh::apps::App draft;
    draft.name = "Client";
    draft.kind = lugh::apps::Kind::web;
    draft.auth = lugh::apps::ClientAuth::client_secret_basic;
    draft.grants = lugh::apps::kAuthorizationCode | lugh::apps::kRefreshToken;
    draft.redirect_uris = {kRedirect};
    draft.scopes = {"openid", "profile"};
    draft.audiences = {"lugh"};
    draft.first_party = true;
    auto made = wait_for<lugh::Outcome<lugh::apps::Apps::Made>>(
        [&](lugh::Executor executor, auto done) { rig.apps->create(rig.admin, draft, kTestDeadline, executor, done); });
    EXPECT_TRUE(made.ok()) << made.message;
    EXPECT_TRUE(wait_for<lugh::Outcome<lugh::apps::App>>([&](lugh::Executor executor, auto done) {
                  rig.apps->access_set(rig.admin, made.value.app.client_id, staff.id, true, kTestDeadline, executor, done);
                }).ok());
    return {made.value.app, std::string(lugh::secret_text(*made.value.secret))};
  }

  // Signed in through the code flow: the token endpoint's answer.
  boost::json::value tokens_for(const lugh::apps::App& app, const std::string& secret) {
    const auto first =
        rig.get("/oauth2/authorize?response_type=code&client_id=" + app.client_id + "&redirect_uri=" + dannan::encoding::percent_encode(kRedirect) +
                "&scope=openid%20profile&state=s&nonce=n&code_challenge=" + kChallenge + "&code_challenge_method=S256");
    const auto form = rig.get(first.location());
    const auto resume = form.between("name=\"continue\" value=\"", "\"");
    rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}, {"continue", resume}});
    const auto factor = rig.get("/signin/factor");
    const auto done = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
    const auto back = rig.get(done.location()).location();
    const auto tokens = rig.request(verb::post, "/oauth2/token",
                                    {{"grant_type", "authorization_code"},
                                     {"code", dannan::encoding::percent_decode(query_value(back, "code"), dannan::encoding::Decoding::form)},
                                     {"redirect_uri", kRedirect},
                                     {"code_verifier", kVerifier}},
                                    {{"Authorization", basic(app.client_id, secret)}});
    EXPECT_EQ(tokens.status, 200u) << tokens.body;
    return boost::json::parse(tokens.body);
  }

  SigninRig rig;
  lugh::directory::User alice;
  lugh::directory::Group staff;
};

}  // namespace

// RFC 9700 section 4.14.2: two rotations of one refresh token raced, and this one lost; it is the
// reuse, so the family is revoked and neither token works.
TEST_F(StoreFaultsTest, ARefreshRotationThatLostARaceRevokesTheFamily) {
  const auto [app, secret] = web_app();
  const auto tokens = tokens_for(app, secret);
  const auto refresh = std::string(tokens.at("refresh_token").as_string());
  const auto rotate = [&] {
    return rig.request(verb::post, "/oauth2/token", {{"grant_type", "refresh_token"}, {"refresh_token", refresh}},
                       {{"Authorization", basic(app.client_id, secret)}});
  };
  rig.store->fail_writes(lugh::oauth::RefreshTokens::kTable, StoreError::conflict);
  EXPECT_EQ(error_of(rotate()), "invalid_grant");
  EXPECT_TRUE(rig.audited("refresh.revoke"));
  EXPECT_EQ(error_of(rotate()), "invalid_grant") << "the family is gone";
  const auto inspected = rig.request(verb::post, "/oauth2/introspect", {{"token", refresh}}, {{"Authorization", basic(app.client_id, secret)}});
  EXPECT_EQ(boost::json::parse(inspected.body).at("active"), false);
}

// A store that fails a rotation outright is a server error, and the token still works after.
TEST_F(StoreFaultsTest, ARefreshRotationTheStoreFailedIsAServerError) {
  const auto [app, secret] = web_app();
  const auto refresh = std::string(tokens_for(app, secret).at("refresh_token").as_string());
  const auto rotate = [&] {
    return rig.request(verb::post, "/oauth2/token", {{"grant_type", "refresh_token"}, {"refresh_token", refresh}},
                       {{"Authorization", basic(app.client_id, secret)}});
  };
  rig.store->fail_writes(lugh::oauth::RefreshTokens::kTable, StoreError::failed);
  const auto failed = rotate();
  EXPECT_EQ(failed.status, 500u);
  EXPECT_EQ(error_of(failed), "server_error");
  EXPECT_EQ(rotate().status, 200u);
}

// The client cannot be checked when its record cannot be read: a server error, never
// invalid_client, at each endpoint that authenticates one.
TEST_F(StoreFaultsTest, AClientThatCannotBeReadIsAServerError) {
  const auto [app, secret] = web_app();
  for (const auto* path : {"/oauth2/token", "/oauth2/introspect", "/oauth2/device", "/oauth2/par"}) {
    rig.store->fail_reads(lugh::apps::kTable);
    const auto answer =
        rig.request(verb::post, path, {{"grant_type", "client_credentials"}, {"token", "x"}}, {{"Authorization", basic(app.client_id, secret)}});
    EXPECT_EQ(answer.status, 500u) << path << ": " << answer.body;
    EXPECT_EQ(error_of(answer), "server_error") << path;
  }
}

// Enrolment spends the link and then sets the password; when the password cannot be written the
// sign-in fails (the link is spent, as the log says), and nothing is signed in.
TEST_F(StoreFaultsTest, AnEnrolmentWhosePasswordCannotBeWrittenFails) {
  const auto bob = rig.person("bob");
  const auto link = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                      rig.links->issue(rig.admin, bob.id, kTestDeadline, executor, done);
                    }).value;
  const std::string token(lugh::secret_text(link));
  const auto set = rig.get("/signin/enrol/" + token);
  rig.store->fail_writes(lugh::authn::Passwords::kTable, StoreError::failed);
  const auto answer = rig.post("/signin/enrol/" + token, {{"csrf", set.csrf()}, {"password", kPassword}, {"password_again", kPassword}});
  EXPECT_EQ(answer.status, 500u) << answer.body;
  EXPECT_TRUE(answer.says("Signing in could not be completed"));
  EXPECT_FALSE(rig.jar.count("__Host-lugh_session"));
}

// Userinfo whose application cannot be read: a server error, not a refusal of the token.
TEST_F(StoreFaultsTest, UserinfoWhoseApplicationCannotBeReadIsAServerError) {
  const auto [app, secret] = web_app();
  const auto access = std::string(tokens_for(app, secret).at("access_token").as_string());
  rig.store->fail_reads(lugh::apps::kTable);
  const auto info = rig.request(verb::get, "/oauth2/userinfo", {}, {{"Authorization", "Bearer " + access}});
  EXPECT_EQ(info.status, 500u) << info.body;
  EXPECT_EQ(rig.request(verb::get, "/oauth2/userinfo", {}, {{"Authorization", "Bearer " + access}}).status, 200u);
}

// A TOTP code is spent by writing its step; a write that lost to another use of the same code
// at the same moment is that code's replay, refused.
TEST_F(StoreFaultsTest, ACodeSpentAtTheSameMomentElsewhereIsRefused) {
  rig.advance(std::chrono::seconds(30));
  rig.store->fail_writes(lugh::authn::Factors::kTable, StoreError::conflict);
  EXPECT_EQ(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
              rig.factors->totp_check(alice.id, rig.code_for(rig.secret), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  rig.store->fail_writes(lugh::authn::Factors::kTable, StoreError::failed);
  EXPECT_EQ(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
              rig.factors->totp_check(alice.id, rig.code_for(rig.secret), kTestDeadline, executor, done);
            }).fault,
            Fault::failed);
}

// A recovery code's slot is spent the same way.
TEST_F(StoreFaultsTest, ARecoveryCodeSpentAtTheSameMomentElsewhereIsRefused) {
  ASSERT_FALSE(rig.recovery.empty());
  rig.store->fail_writes(lugh::authn::Factors::kTable, StoreError::conflict);
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              rig.factors->recovery_use(alice.id, copy_of(rig.recovery[0]), kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  rig.store->fail_writes(lugh::authn::Factors::kTable, StoreError::failed);
  EXPECT_EQ(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
              rig.factors->recovery_use(alice.id, copy_of(rig.recovery[0]), kTestDeadline, executor, done);
            }).fault,
            Fault::failed);
  EXPECT_TRUE(wait_for<lugh::Outcome<std::size_t>>([&](lugh::Executor executor, auto done) {
                rig.factors->recovery_use(alice.id, copy_of(rig.recovery[0]), kTestDeadline, executor, done);
              }).ok())
      << "unspent after both";
}

// An application whose record cannot be written is not changed, and says the store failed.
TEST_F(StoreFaultsTest, AnApplicationThatCannotBeWrittenIsNotChanged) {
  const auto [app, secret] = web_app();
  auto changed = app;
  changed.name = "Renamed";
  rig.store->fail_writes(lugh::apps::kTable, StoreError::failed);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::apps::App>>([&](lugh::Executor executor, auto done) {
              rig.apps->replace(rig.admin, changed, std::nullopt, kTestDeadline, executor, done);
            }).fault,
            Fault::failed);
  EXPECT_EQ(read_value<std::optional<lugh::apps::App>>([&](lugh::Executor executor, auto done) {
              rig.apps->app(app.client_id, kTestDeadline, executor, done);
            })->name,
            "Client");
}

// A POSIX number that cannot be counted out makes no user: the number is never given twice.
TEST_F(StoreFaultsTest, APosixNumberThatCannotBeCountedMakesNoUser) {
  rig.directory->numbers_set(std::make_shared<lugh::directory::PosixNumbers>(rig.store, lugh::directory::PosixNumbers::Range{10000, 19999},
                                                                             lugh::directory::PosixNumbers::Range{20000, 29999}));
  rig.store->fail_writes(lugh::directory::PosixNumbers::kTable, StoreError::failed);
  const auto made = wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
    rig.directory->create_user(rig.admin, {lugh::directory::Kind::person, "carol", "carol@example.com", "Carol", "", ""}, kTestDeadline, executor, done);
  });
  EXPECT_EQ(made.fault, Fault::failed);
  EXPECT_EQ(rig.person("carol").posix_number, 10000u);
}

// Removing a user whose memberships cannot be read still removes the user; the memberships are
// left for the next removal pass, as the log says.
TEST_F(StoreFaultsTest, RemovingAUserWhoseMembershipsCannotBeReadStillRemovesThem) {
  rig.store->fail_reads(lugh::directory::kMemberships);
  ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->remove_user(rig.admin, alice.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->user(alice.id, kTestDeadline, executor, done); }));
  EXPECT_NE(rig.logger->text().find("cannot read memberships to remove"), std::string::npos);
}

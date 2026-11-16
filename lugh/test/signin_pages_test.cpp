//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/genesis.h"
#include "lugh/scopes/scope.h"
#include "lugh/signin/html.h"
#include "lugh/test/fixtures/signin_rig.h"

using lugh::http::verb;

namespace {

constexpr const char* kPassword = "correct horse battery";

}  // namespace

// The whole of an ordinary sign-in: the password, a TOTP code, the session, signing out.
TEST(SigninPages, PasswordThenCodeThenSignedIn) {
  SigninRig rig;
  rig.enrolled("alice");

  const auto form = rig.get("/signin");
  ASSERT_EQ(form.status, 200u);
  EXPECT_FALSE(form.csrf().empty());
  EXPECT_TRUE(rig.jar.count("__Host-lugh_signin"));
  EXPECT_EQ(form.header("Content-Security-Policy"), lugh::signin::kPagePolicy);
  EXPECT_EQ(form.header("Cache-Control"), "no-store");

  const auto password = rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}});
  ASSERT_EQ(password.status, 303u) << password.body;
  EXPECT_EQ(password.location(), "/signin/factor");
  EXPECT_FALSE(rig.jar.count("__Host-lugh_session"));

  const auto factor = rig.get("/signin/factor");
  ASSERT_EQ(factor.status, 200u);
  const auto signed_in = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
  ASSERT_EQ(signed_in.status, 303u) << signed_in.body;
  EXPECT_EQ(signed_in.location(), "/signin/done");
  ASSERT_TRUE(rig.jar.count("__Host-lugh_session"));
  EXPECT_NE(signed_in.header("Set-Cookie").find("HttpOnly"), std::string::npos);
  EXPECT_TRUE(rig.audited("session.start"));

  const auto done = rig.get("/signin/done");
  ASSERT_EQ(done.status, 200u);
  EXPECT_TRUE(done.says("alice"));
  // Signed in, the form sends you on.
  EXPECT_EQ(rig.get("/signin").location(), "/signin/done");

  // Signing out needs the session's own token.
  const auto handle = rig.jar.at("__Host-lugh_session");
  EXPECT_EQ(rig.post("/signout", {{"csrf", "forged"}}).status, 403u);
  EXPECT_TRUE(rig.sessions->find(handle));
  const auto out = rig.post("/signout", {{"csrf", done.csrf()}});
  ASSERT_EQ(out.status, 200u);
  EXPECT_FALSE(rig.jar.count("__Host-lugh_session"));
  EXPECT_FALSE(rig.sessions->find(handle));
  EXPECT_TRUE(rig.audited("session.end"));
  EXPECT_EQ(rig.get("/signin/done").location(), "/signin");
}

TEST(SigninPages, RefusalsSayLittleAndEscapeWhatTheyRepeat) {
  SigninRig rig;
  rig.enrolled("alice");

  const auto wrong = rig.sign_in("alice", "not the password");
  EXPECT_EQ(wrong.status, 401u);
  EXPECT_TRUE(wrong.says("That name and password do not match."));
  const auto unknown = rig.sign_in("<script>x</script>", "whatever it is");
  EXPECT_EQ(unknown.status, 401u);
  EXPECT_TRUE(unknown.says("That name and password do not match."));
  EXPECT_FALSE(unknown.says("<script>x"));
  EXPECT_TRUE(unknown.says("&lt;script&gt;x&lt;/script&gt;"));

  // A form without the visitor's token, as another site would post it.
  const auto forged = rig.post("/signin", {{"csrf", "made up"}, {"login", "alice"}, {"password", kPassword}});
  EXPECT_EQ(forged.status, 403u);
  rig.jar.clear();
  const auto no_cookie = rig.post("/signin", {{"login", "alice"}, {"password", kPassword}});
  EXPECT_EQ(no_cookie.status, 403u);
  EXPECT_EQ(rig.request(verb::post, "/signin").status, 403u);
}

TEST(SigninPages, AWrongCodeIsToldAndTheLimitHolds) {
  SigninRig rig;
  rig.enrolled("alice");
  ASSERT_EQ(rig.sign_in("alice", kPassword).location(), "/signin/factor");
  for (int i = 0; i < 4; ++i) {
    const auto factor = rig.get("/signin/factor");
    const auto wrong = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", "000000"}});
    EXPECT_EQ(wrong.status, 401u);
    EXPECT_TRUE(wrong.says("That code is not right."));
  }
  const auto factor = rig.get("/signin/factor");
  const auto ended = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", "000000"}});
  EXPECT_EQ(ended.status, 401u);
  EXPECT_TRUE(ended.says("Start again"));
  // The sign-in is over: the code page sends you back to the start.
  EXPECT_EQ(rig.get("/signin/factor").location(), "/signin");
}

TEST(SigninPages, ARecoveryCodeSaysHowManyAreLeft) {
  SigninRig rig;
  rig.enrolled("alice");
  ASSERT_EQ(rig.sign_in("alice", kPassword).location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  const auto used = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"recovery", std::string(lugh::secret_text(rig.recovery.at(0)))}});
  ASSERT_EQ(used.status, 200u) << used.body;
  EXPECT_TRUE(used.says("You have 9 left"));
  EXPECT_TRUE(rig.jar.count("__Host-lugh_session"));
}

// A new person: the enrolment link, a password, a TOTP factor, the recovery codes once.
TEST(SigninPages, EnrolmentFromALink) {
  SigninRig rig;
  const auto bob = rig.person("bob");
  const auto token =
      wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) { rig.links->issue(rig.admin, bob.id, kTestDeadline, executor, done); });
  ASSERT_TRUE(token.ok());
  const auto path = "/signin/enrol/" + std::string(lugh::secret_text(token.value));

  const auto form = rig.get(path);
  ASSERT_EQ(form.status, 200u);
  EXPECT_TRUE(rig.post(path, {{"csrf", form.csrf()}, {"password", kPassword}, {"password_again", "something else"}}).says("not the same"));
  const auto set = rig.post(path, {{"csrf", form.csrf()}, {"password", kPassword}, {"password_again", kPassword}});
  ASSERT_EQ(set.status, 303u) << set.body;
  EXPECT_EQ(set.location(), "/signin/enrol/totp");

  const auto add = rig.get("/signin/enrol/totp");
  ASSERT_EQ(add.status, 200u) << add.body;
  const auto secret = add.totp_secret();
  ASSERT_FALSE(secret.empty());
  EXPECT_TRUE(add.says("otpauth://totp/"));
  EXPECT_TRUE(add.says("<svg class=\"qr\""));

  // A wrong code keeps the same secret on the page.
  const auto wrong = rig.post("/signin/enrol/totp", {{"csrf", add.csrf()}, {"code", "000000"}});
  EXPECT_EQ(wrong.status, 401u);
  EXPECT_EQ(wrong.totp_secret(), secret);

  const auto codes = rig.post("/signin/enrol/totp", {{"csrf", add.csrf()}, {"code", rig.code_for(lugh::text_secret(secret))}});
  ASSERT_EQ(codes.status, 200u) << codes.body;
  EXPECT_TRUE(codes.says("Your recovery codes"));
  EXPECT_TRUE(rig.jar.count("__Host-lugh_session"));

  // The link is spent.
  const auto again = rig.get(path);
  EXPECT_EQ(rig.post(path, {{"csrf", again.csrf()}, {"password", kPassword}, {"password_again", kPassword}}).status, 401u);
}

// Root's first sign-in goes from genesis's password to enrolment, once.
TEST(SigninPages, RootsFirstSignIn) {
  SigninRig rig;
  const auto password = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
    lugh::authn::Genesis(rig.directory, rig.passwords, rig.links, rig.grants, rig.audit).run(kTestDeadline, executor, done);
  });
  ASSERT_TRUE(password.ok());
  const auto first = rig.sign_in("root", std::string(lugh::secret_text(password.value)));
  ASSERT_EQ(first.status, 303u) << first.body;
  EXPECT_EQ(first.location(), "/signin/enrol/totp");
  const auto add = rig.get("/signin/enrol/totp");
  const auto codes = rig.post("/signin/enrol/totp", {{"csrf", add.csrf()}, {"code", rig.code_for(lugh::text_secret(add.totp_secret()))}});
  ASSERT_EQ(codes.status, 200u) << codes.body;

  // Root's session holds every Lugh scope; a TOTP sign-in is mfa, so administering waits for a
  // passkey (the maintainer, 2026-11-16).
  const auto me = rig.get("/api/v1/me");
  ASSERT_EQ(me.status, 200u) << me.body;
  const auto body = boost::json::parse(me.body);
  EXPECT_EQ(body.at("user").at("name"), "root");
  EXPECT_EQ(body.at("scopes").as_array().size(), lugh::scopes::lugh_scopes().size());
  const auto users = rig.get("/api/v1/users");
  EXPECT_EQ(users.status, 403u);
  EXPECT_EQ(boost::json::parse(users.body).at("error").at("code"), "phr_required");
}

// A session opens the API; a change through it needs its CSRF token, which /api/v1/me gives.
TEST(SigninPages, TheApiThroughASession) {
  SigninRig rig;
  rig.enrolled("alice");
  EXPECT_EQ(rig.get("/api/v1/me").status, 401u);
  ASSERT_EQ(rig.sign_in("alice", kPassword).location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  ASSERT_EQ(rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}}).status, 303u);

  const auto me = rig.get("/api/v1/me");
  ASSERT_EQ(me.status, 200u) << me.body;
  const auto body = boost::json::parse(me.body);
  EXPECT_EQ(body.at("session").at("acr"), "urn:lugh:acr:mfa");
  EXPECT_TRUE(body.at("scopes").as_array().empty());
  const auto token = std::string(body.at("session").at("csrf_token").as_string());

  // Alice holds no scope: reading users is refused for want of one, not for want of a caller.
  EXPECT_EQ(rig.get("/api/v1/users").status, 403u);
  // A change without the token is no caller at all.
  EXPECT_EQ(rig.request(verb::post, "/api/v1/users", {}, {{"Content-Type", "application/json"}}).status, 401u);
  EXPECT_EQ(rig.request(verb::post, "/api/v1/users", {}, {{"Content-Type", "application/json"}, {"X-CSRF-Token", token}}).status, 403u);
  EXPECT_EQ(rig.request(verb::post, "/api/v1/users", {}, {{"Content-Type", "application/json"}, {"X-CSRF-Token", token + "x"}}).status, 401u);
}

// The dashboard (P7) sends a sign-in, and a step-up, with continue=dashboard, and is where it
// comes back: the root, never a place the request names.
TEST(SigninPages, TheDashboardIsWhereItsSignInReturns) {
  SigninRig rig;
  rig.enrolled("alice");
  const auto form = rig.get("/signin?continue=dashboard");
  ASSERT_EQ(form.status, 200u);
  ASSERT_EQ(rig.post("/signin", {{"csrf", form.csrf()}, {"login", "alice"}, {"password", kPassword}, {"continue", "dashboard"}}).location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  const auto done = rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}});
  EXPECT_EQ(done.status, 303u) << done.body;
  EXPECT_EQ(done.location(), "/");

  // Signed in at mfa, asking for phr: the form again, not "signed in already".
  const auto step_up = rig.get("/signin?continue=dashboard&acr=urn:lugh:acr:phr");
  EXPECT_EQ(step_up.status, 200u);
  EXPECT_FALSE(step_up.csrf().empty());
  // Anything else as continue goes nowhere but the sign-in's own pages.
  EXPECT_EQ(rig.get("/signin").location(), "/signin/done");
  EXPECT_EQ(rig.get("/signin?continue=https://evil.example/").location(), "/signin/done");
}

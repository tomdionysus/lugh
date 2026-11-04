//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/signin_rig.h"

using lugh::http::verb;

namespace {

constexpr const char* kPassword = "correct horse battery";

class SessionRoutesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    alice = rig.enrolled("alice");
    signed_in(rig);
  }

  // Through the pages, as `browser`'s cookies hold it.
  void signed_in(SigninRig& browser, const std::string& password = kPassword) {
    ASSERT_EQ(browser.sign_in("alice", password).location(), "/signin/factor");
    const auto factor = browser.get("/signin/factor");
    rig.advance(std::chrono::seconds(30));
    ASSERT_EQ(browser.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}}).status, 303u);
  }

  // A second browser for the same person: the rig's routes, cookies of its own.
  std::map<std::string, std::string> second_browser() {
    const auto mine = rig.jar;
    rig.jar.clear();
    signed_in(rig);
    auto theirs = rig.jar;
    rig.jar = mine;
    return theirs;
  }

  // Alice in a group holding `scopes`, read into her sessions at once.
  void grant(std::vector<std::string> scopes) {
    const auto group = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                         rig.directory->create_group(rig.admin, "ops", "", kTestDeadline, executor, done);
                       }).value;
    ASSERT_TRUE(wait_for<lugh::Outcome<lugh::scopes::Granted>>([&](lugh::Executor executor, auto done) {
                  rig.grants->group_set(rig.admin, group.id, scopes, std::nullopt, kTestDeadline, executor, done);
                }).ok());
    ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                  rig.directory->add_member(rig.admin, group.id, alice.id, kTestDeadline, executor, done);
                }).ok());
    ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { rig.sessions->refresh(kTestDeadline, executor, done); }).ok);
  }

  SigninRig rig;
  lugh::directory::User alice;
};

}  // namespace

TEST_F(SessionRoutesTest, YourOwnSessions) {
  const auto other = second_browser();
  const auto listed = rig.get("/api/v1/me/sessions");
  ASSERT_EQ(listed.status, 200u) << listed.body;
  const auto sessions = boost::json::parse(listed.body).at("sessions").as_array();
  ASSERT_EQ(sessions.size(), 2u);
  std::string other_sid;
  int current = 0;
  for (const auto& one : sessions) {
    EXPECT_EQ(one.at("acr"), "urn:lugh:acr:mfa");
    if (one.at("current").as_bool()) {
      ++current;
    } else {
      other_sid = std::string(one.at("sid").as_string());
    }
  }
  EXPECT_EQ(current, 1);

  // Ending the other: its cookie opens nothing after.
  EXPECT_EQ(rig.json(verb::delete_, "/api/v1/me/sessions/" + other_sid, "").status, 204u);
  EXPECT_FALSE(rig.sessions->find(other.at("__Host-lugh_session")));
  EXPECT_EQ(rig.json(verb::delete_, "/api/v1/me/sessions/" + other_sid, "").status, 404u);
  EXPECT_EQ(boost::json::parse(rig.get("/api/v1/me/sessions").body).at("sessions").as_array().size(), 1u);
}

// A password change ends every other session of the person's, and only through their own.
TEST_F(SessionRoutesTest, ChangingYourPassword) {
  const auto other = second_browser();
  EXPECT_EQ(rig.json(verb::post, "/api/v1/me/password", R"({"current":"not it","new":"a much better passphrase"})").status, 403u);
  EXPECT_EQ(rig.json(verb::post, "/api/v1/me/password", R"({"current":"correct horse battery","new":"short"})").status, 400u);
  const auto changed = rig.json(verb::post, "/api/v1/me/password", R"({"current":"correct horse battery","new":"a much better passphrase"})");
  ASSERT_EQ(changed.status, 204u) << changed.body;
  EXPECT_FALSE(rig.sessions->find(other.at("__Host-lugh_session")));
  EXPECT_EQ(rig.get("/api/v1/me").status, 200u);
  EXPECT_TRUE(rig.audited("password.set"));

  // The new one signs in; the old one does not.
  rig.jar.clear();
  EXPECT_EQ(rig.sign_in("alice", kPassword).status, 401u);
  rig.advance(std::chrono::hours(2));
  EXPECT_EQ(rig.sign_in("alice", "a much better passphrase").location(), "/signin/factor");
}

TEST_F(SessionRoutesTest, AnAdministratorsView) {
  EXPECT_EQ(rig.get("/api/v1/users/" + alice.id + "/sessions").status, 403u);
  grant({"lugh:directory.read", "lugh:sessions.write", "lugh:directory.write"});
  const auto listed = rig.get("/api/v1/users/" + alice.id + "/sessions");
  ASSERT_EQ(listed.status, 200u) << listed.body;
  EXPECT_EQ(boost::json::parse(listed.body).at("sessions").as_array().size(), 1u);
  const auto ended = rig.json(verb::delete_, "/api/v1/users/" + alice.id + "/sessions", "");
  ASSERT_EQ(ended.status, 200u) << ended.body;
  EXPECT_EQ(boost::json::parse(ended.body).at("ended"), 1);
  EXPECT_EQ(rig.get("/api/v1/me").status, 401u);
}

// Disabling a person ends their sessions at once, not at the next refresh.
TEST_F(SessionRoutesTest, DisablingEndsSessionsAtOnce) {
  const auto other = second_browser();
  grant({"lugh:directory.read", "lugh:directory.write"});
  ASSERT_EQ(rig.sessions->of_user(alice.id).size(), 2u);
  const auto version = read_value<std::optional<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                         rig.directory->user(alice.id, kTestDeadline, executor, done);
                       })->version;
  const auto token = std::string(boost::json::parse(rig.get("/api/v1/me").body).at("session").at("csrf_token").as_string());
  const auto disabled = rig.send(verb::patch, "/api/v1/users/" + alice.id, R"({"disabled":true})",
                                 {{"Content-Type", "application/json"}, {"X-CSRF-Token", token}, {"If-Match", "\"" + std::to_string(version) + "\""}});
  EXPECT_EQ(disabled.status, 200u) << disabled.body;
  EXPECT_TRUE(rig.sessions->of_user(alice.id).empty());
  EXPECT_FALSE(rig.sessions->find(other.at("__Host-lugh_session")));
}

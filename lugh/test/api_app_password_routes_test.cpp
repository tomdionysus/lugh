//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/api_rig.h"
#include "lugh/test/fixtures/signin_rig.h"

using lugh::http::verb;

TEST(AppPasswordRoutes, AnAdministratorMakesListsAndRevokes) {
  ApiRig rig;
  const auto id = rig.made_user("alice");
  const auto path = "/api/v1/users/" + id + "/app-passwords";

  const auto made = rig.post(path, R"({"name":"nas","scopes":["lugh:directory.read","lugh:directory.write"],"networks":["10.0.0.0/8"]})");
  ASSERT_EQ(made.status, 201u) << made.response->body();
  const auto password = std::string(made.body.at("password").as_string());
  EXPECT_EQ(password.size(), 39u);
  EXPECT_EQ(made.body.at("networks"), (boost::json::array{"10.0.0.0/8"}));

  const auto listed = rig.get(path);
  ASSERT_EQ(listed.status, 200u);
  ASSERT_EQ(listed.body.at("app_passwords").as_array().size(), 1u);
  EXPECT_EQ(listed.response->body().find(password), std::string::npos);

  const auto app_password = std::string(made.body.at("id").as_string());
  EXPECT_EQ(rig.request(verb::delete_, path + "/" + app_password).status, 204u);
  EXPECT_EQ(rig.request(verb::delete_, path + "/" + app_password).status, 404u);
  EXPECT_EQ(rig.post(path, R"({"name":"x","scopes":"lugh:directory.read"})").status, 400u);
  EXPECT_EQ(rig.request(verb::post, path, R"({"name":"x"})", {}, "Bearer reader").status, 403u);
  EXPECT_EQ(rig.request(verb::get, path, "", {}, "Bearer reader").status, 200u);
}

// A person makes their own, and cannot give one more than they hold.
TEST(AppPasswordRoutes, YourOwnWithinYourScopes) {
  SigninRig rig;
  rig.enrolled("alice");
  ASSERT_EQ(rig.sign_in("alice", "correct horse battery").location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  ASSERT_EQ(rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}}).status, 303u);
  // Alice holds no scope, so not even the default one.
  EXPECT_EQ(rig.json(verb::post, "/api/v1/me/app-passwords", R"({"name":"mail"})").status, 403u);

  // Given directory.read through a group, she can make one carrying it, and no more.
  const auto staff = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                       rig.directory->create_group(rig.admin, "staff", "", kTestDeadline, executor, done);
                     }).value;
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::scopes::Granted>>([&](lugh::Executor executor, auto done) {
                rig.grants->group_set(rig.admin, staff.id, {"lugh:directory.read"}, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  const auto alice = read_value<std::optional<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->user_by_name("alice", kTestDeadline, executor, done); });
  ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->add_member(rig.admin, staff.id, alice->id, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { rig.sessions->refresh(kTestDeadline, executor, done); }).ok);

  const auto made = rig.json(verb::post, "/api/v1/me/app-passwords", R"({"name":"mail"})");
  ASSERT_EQ(made.status, 201u) << made.body;
  EXPECT_EQ(rig.json(verb::post, "/api/v1/me/app-passwords", R"({"name":"more","scopes":["lugh:directory.write"]})").status, 403u);
  const auto listed = rig.get("/api/v1/me/app-passwords");
  ASSERT_EQ(listed.status, 200u) << listed.body;
  EXPECT_EQ(boost::json::parse(listed.body).at("app_passwords").as_array().size(), 1u);
}

// One that may change anything administers over LDAP, where the router's gate does not reach, so a
// session must be at phr to make it (the maintainer, 2026-11-16); a read-only one is open at mfa.
TEST(AppPasswordRoutes, OneThatMayChangeAnythingNeedsPhr) {
  SigninRig rig;
  const auto alice = rig.enrolled("alice");
  ASSERT_EQ(rig.sign_in("alice", "correct horse battery").location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  ASSERT_EQ(rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}}).status, 303u);
  const auto ops = wait_for<lugh::Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                     rig.directory->create_group(rig.admin, "ops", "", kTestDeadline, executor, done);
                   }).value;
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::scopes::Granted>>([&](lugh::Executor executor, auto done) {
                rig.grants->group_set(rig.admin, ops.id, {"lugh:directory.read", "lugh:directory.write"}, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<lugh::Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->add_member(rig.admin, ops.id, alice.id, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { rig.sessions->refresh(kTestDeadline, executor, done); }).ok);

  EXPECT_EQ(rig.json(verb::post, "/api/v1/me/app-passwords", R"({"name":"mail","scopes":["lugh:directory.read"]})").status, 201u);
  const auto refused = rig.json(verb::post, "/api/v1/me/app-passwords", R"({"name":"provisioning","scopes":["lugh:directory.write"]})");
  EXPECT_EQ(refused.status, 403u);
  EXPECT_EQ(boost::json::parse(refused.body).at("error").at("code"), "phr_required");

  rig.at_phr(alice.id);
  ASSERT_FALSE(HasFatalFailure());
  EXPECT_EQ(rig.json(verb::post, "/api/v1/me/app-passwords", R"({"name":"provisioning","scopes":["lugh:directory.write"]})").status, 201u);
}

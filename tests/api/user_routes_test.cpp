//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "api/user_routes.h"

#include <gtest/gtest.h>

#include "helpers/api_rig.h"

using lugh::http::field;
using lugh::http::verb;

namespace {

class UserRoutesTest : public ::testing::Test {
 protected:
  ApiRig rig;
};

}  // namespace

TEST_F(UserRoutesTest, NoCredentialNoAnswer) {
  const auto answer = rig.request(verb::get, "/api/v1/users", "", {}, "");
  EXPECT_EQ(answer.status, 401u);
  EXPECT_EQ(answer.error(), "unauthorized");
  EXPECT_EQ(answer.header(field::www_authenticate), "Bearer realm=\"lugh\"");
  EXPECT_EQ(rig.request(verb::get, "/api/v1/users", "", {}, "Bearer wrong").status, 401u);
}

TEST_F(UserRoutesTest, AReaderCannotWrite) {
  EXPECT_EQ(rig.request(verb::get, "/api/v1/users", "", {}, "Bearer reader").status, 200u);
  const auto refused = rig.request(verb::post, "/api/v1/users", R"({"name":"alice"})", {}, "Bearer reader");
  EXPECT_EQ(refused.status, 403u);
  EXPECT_EQ(refused.error(), "forbidden");
  EXPECT_TRUE(run(rig.directory->users()).empty());
}

TEST_F(UserRoutesTest, CreateThenRead) {
  const auto made = rig.post("/api/v1/users", R"({"name":"Alice","email":"Alice@Example.com","display_name":"Alice Smith"})");
  ASSERT_EQ(made.status, 201u) << made.response->body();
  const auto id = std::string(made.body.at("id").as_string());
  EXPECT_EQ(made.header(field::location), "/api/v1/users/" + id);
  EXPECT_EQ(made.header(field::etag), "\"1\"");
  EXPECT_EQ(made.body.at("name"), "alice");
  EXPECT_EQ(made.body.at("email"), "alice@example.com");
  EXPECT_EQ(made.body.at("kind"), "person");
  EXPECT_EQ(made.body.at("enrolled"), false);
  EXPECT_EQ(made.body.at("created_at"), "2026-10-18T00:00:00Z");

  const auto read = rig.get("/api/v1/users/" + id);
  EXPECT_EQ(read.status, 200u);
  EXPECT_EQ(read.body.at("display_name"), "Alice Smith");
  EXPECT_EQ(read.header(field::etag), "\"1\"");
  EXPECT_EQ(read.header(field::cache_control), "no-store");

  // The audit log names the caller and where they called from.
  const auto entry = run(rig.audit->entries(1, 1)).at(0);
  EXPECT_EQ(entry.event.actor, ApiRig::kAdministrator);
  EXPECT_EQ(entry.event.source, "192.0.2.50");
}

TEST_F(UserRoutesTest, ListAndFind) {
  rig.made_user("alice");
  rig.made_user("bob");
  EXPECT_EQ(rig.get("/api/v1/users").body.at("users").as_array().size(), 2u);
  const auto by_name = rig.get("/api/v1/users?name=ALICE").body.at("users").as_array();
  ASSERT_EQ(by_name.size(), 1u);
  EXPECT_EQ(by_name[0].at("name"), "alice");
  EXPECT_EQ(rig.get("/api/v1/users?email=bob%40example.com").body.at("users").as_array().size(), 1u);
  EXPECT_TRUE(rig.get("/api/v1/users?name=carol").body.at("users").as_array().empty());
}

TEST_F(UserRoutesTest, BadBodiesAreRefusedWithReasons) {
  EXPECT_EQ(rig.post("/api/v1/users", "not json").error(), "invalid");
  EXPECT_EQ(rig.post("/api/v1/users", "[1]").error(), "invalid");
  EXPECT_EQ(rig.post("/api/v1/users", R"({"email":"a@example.com"})").error(), "invalid");
  EXPECT_EQ(rig.post("/api/v1/users", R"({"name":"alice","email":"a@example.com","admin":true})").body.at("error").at("message"), "unknown field admin");
  EXPECT_EQ(rig.post("/api/v1/users", R"({"name":5,"email":"a@example.com"})").body.at("error").at("message"), "name must be a string");
  EXPECT_EQ(rig.post("/api/v1/users", R"({"name":"alice","email":"a@example.com","kind":"robot"})").status, 400u);
  EXPECT_EQ(rig.post("/api/v1/users", R"({"name":"al ice","email":"a@example.com"})").status, 400u);
  EXPECT_TRUE(run(rig.directory->users()).empty());
}

TEST_F(UserRoutesTest, ADuplicateIsAConflict) {
  rig.made_user("alice");
  const auto again = rig.post("/api/v1/users", R"({"name":"ALICE","email":"other@example.com"})");
  EXPECT_EQ(again.status, 409u);
  EXPECT_EQ(again.error(), "duplicate");
}

TEST_F(UserRoutesTest, AServiceNeedsNoAddress) {
  const auto made = rig.post("/api/v1/users", R"({"kind":"service","name":"backup"})");
  ASSERT_EQ(made.status, 201u);
  EXPECT_EQ(made.body.at("kind"), "service");
  EXPECT_EQ(made.body.at("enrolled"), true);
}

TEST_F(UserRoutesTest, UpdatesNeedTheCurrentETag) {
  const auto id = rig.made_user("alice");
  const auto path = "/api/v1/users/" + id;

  const auto without = rig.request(verb::patch, path, R"({"display_name":"A"})");
  EXPECT_EQ(without.status, 428u);
  EXPECT_EQ(without.error(), "if_match_required");

  const auto changed = rig.request(verb::patch, path, R"({"display_name":"Alice S","disabled":true})", {{field::if_match, "\"1\""}});
  ASSERT_EQ(changed.status, 200u) << changed.response->body();
  EXPECT_EQ(changed.body.at("display_name"), "Alice S");
  EXPECT_EQ(changed.body.at("disabled"), true);
  EXPECT_EQ(changed.header(field::etag), "\"3\"");

  const auto stale = rig.request(verb::patch, path, R"({"display_name":"B"})", {{field::if_match, "\"1\""}});
  EXPECT_EQ(stale.status, 412u);
  EXPECT_EQ(stale.error(), "changed");
  EXPECT_EQ(rig.request(verb::patch, path, R"({"display_name":"B"})", {{field::if_match, "W/\"3\""}}).status, 412u);
  EXPECT_EQ(rig.request(verb::patch, path, R"({"display_name":"B"})", {{field::if_match, "*"}}).status, 200u);
  EXPECT_EQ(rig.request(verb::patch, path, R"({"disabled":"yes"})", {{field::if_match, "*"}}).status, 400u);
  EXPECT_EQ(rig.request(verb::patch, "/api/v1/users/nobody", "{}", {{field::if_match, "*"}}).status, 404u);
}

TEST_F(UserRoutesTest, Remove) {
  const auto id = rig.made_user("alice");
  EXPECT_EQ(rig.request(verb::delete_, "/api/v1/users/" + id).status, 428u);
  EXPECT_EQ(rig.request(verb::delete_, "/api/v1/users/" + id, "", {{field::if_match, "\"7\""}}).status, 412u);
  EXPECT_EQ(rig.request(verb::delete_, "/api/v1/users/" + id, "", {{field::if_match, "\"1\""}}).status, 204u);
  EXPECT_EQ(rig.get("/api/v1/users/" + id).status, 404u);
}

TEST_F(UserRoutesTest, TheFirstAdministratorEnrols) {
  const auto id = rig.made_user("alice");
  const auto issued = rig.post("/api/v1/users/" + id + "/enrolment", "");
  ASSERT_EQ(issued.status, 201u) << issued.response->body();
  EXPECT_EQ(issued.body.at("expires_at"), "2026-10-21T00:00:00Z");
  const lugh::Secret token(std::string(issued.body.at("token").as_string()));

  const auto redeemed = run(rig.authenticator->redeem(token, lugh::Secret("correct horse battery"), "192.0.2.1"));
  ASSERT_EQ(redeemed.kind, lugh::authn::Step::Kind::next);
  EXPECT_EQ(redeemed.sign_in.user_id, id);
  EXPECT_EQ(rig.post("/api/v1/users/nobody/enrolment", "").status, 404u);
}

TEST_F(UserRoutesTest, FactorsAreListedWithoutSecrets) {
  const auto alice = rig.enrolled("alice");
  const auto answer = rig.get("/api/v1/users/" + alice.id + "/factors");
  ASSERT_EQ(answer.status, 200u);
  const auto& factors = answer.body.at("factors").as_array();
  ASSERT_EQ(factors.size(), 2u);
  for (const auto& factor : factors) {
    const auto id = std::string(factor.at("id").as_string());
    EXPECT_EQ(id.find('/'), std::string::npos);
    EXPECT_EQ(id.find(alice.id), std::string::npos);
    if (factor.at("kind") == "recovery") EXPECT_EQ(factor.at("remaining"), 10);
  }
  const auto body = answer.response->body();
  EXPECT_EQ(body.find(std::string(rig.secret.reveal())), std::string::npos);
}

TEST_F(UserRoutesTest, RemovingFactorsAndResetting) {
  const auto alice = rig.enrolled("alice");
  std::string totp, recovery;
  const auto listed = rig.get("/api/v1/users/" + alice.id + "/factors");
  for (const auto& factor : listed.body.at("factors").as_array()) {
    (factor.at("kind") == "totp" ? totp : recovery) = std::string(factor.at("id").as_string());
  }
  const auto base = "/api/v1/users/" + alice.id + "/factors/";

  const auto last = rig.request(verb::delete_, base + totp);
  EXPECT_EQ(last.status, 409u);
  EXPECT_EQ(last.error(), "refused");
  EXPECT_EQ(rig.request(verb::delete_, base + recovery).status, 204u);
  EXPECT_EQ(rig.request(verb::delete_, base + "totp-0000").status, 404u);
  EXPECT_EQ(rig.request(verb::delete_, base + "nonsense").status, 404u);

  EXPECT_EQ(rig.post(base + "reset", "").status, 204u);
  EXPECT_TRUE(rig.get("/api/v1/users/" + alice.id + "/factors").body.at("factors").as_array().empty());
  EXPECT_EQ(rig.get("/api/v1/users/" + alice.id).body.at("enrolled"), false);
}

TEST_F(UserRoutesTest, AUsersGroups) {
  const auto id = rig.made_user("alice");
  const auto group = run(rig.directory->create_group(rig.admin, "staff", "")).value;
  run(rig.directory->add_member(rig.admin, group.id, id));
  const auto groups = rig.get("/api/v1/users/" + id + "/groups").body.at("groups").as_array();
  ASSERT_EQ(groups.size(), 1u);
  EXPECT_EQ(groups[0].at("name"), "staff");
  EXPECT_EQ(rig.get("/api/v1/users/nobody/groups").status, 404u);
}

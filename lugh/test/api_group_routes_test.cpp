//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/api/group_routes.h"
#include "lugh/test/fixtures/api_rig.h"

using lugh::http::field;
using lugh::http::verb;

TEST(GroupRoutes, CreateUpdateRemove) {
  ApiRig rig;
  const auto made = rig.post("/api/v1/groups", R"({"name":"Staff","description":"Everyone"})");
  ASSERT_EQ(made.status, 201u) << made.response->body();
  const auto id = std::string(made.body.at("id").as_string());
  EXPECT_EQ(made.body.at("name"), "staff");
  EXPECT_EQ(made.header(field::location), "/api/v1/groups/" + id);

  EXPECT_EQ(rig.post("/api/v1/groups", R"({"name":"STAFF"})").error(), "duplicate");
  EXPECT_EQ(rig.post("/api/v1/groups", R"({"description":"x"})").status, 400u);
  EXPECT_EQ(rig.get("/api/v1/groups?name=staff").body.at("groups").as_array().size(), 1u);

  const auto renamed = rig.request(verb::patch, "/api/v1/groups/" + id, R"({"name":"people"})", {{field::if_match, "\"1\""}});
  ASSERT_EQ(renamed.status, 200u);
  EXPECT_EQ(renamed.body.at("name"), "people");
  EXPECT_EQ(renamed.header(field::etag), "\"2\"");
  EXPECT_EQ(rig.request(verb::patch, "/api/v1/groups/" + id, R"({"name":"x"})").status, 428u);

  EXPECT_EQ(rig.request(verb::delete_, "/api/v1/groups/" + id, "", {{field::if_match, "\"2\""}}).status, 204u);
  EXPECT_EQ(rig.get("/api/v1/groups/" + id).status, 404u);
}

TEST(GroupRoutes, Members) {
  ApiRig rig;
  const auto alice = rig.made_user("alice");
  const auto group = std::string(rig.post("/api/v1/groups", R"({"name":"staff"})").body.at("id").as_string());
  const auto member = "/api/v1/groups/" + group + "/members/" + alice;

  EXPECT_EQ(rig.request(verb::put, member).status, 204u);
  EXPECT_EQ(rig.request(verb::put, member).status, 204u);
  const auto members = rig.get("/api/v1/groups/" + group + "/members").body.at("members").as_array();
  ASSERT_EQ(members.size(), 1u);
  EXPECT_EQ(members[0].at("name"), "alice");

  EXPECT_EQ(rig.request(verb::put, "/api/v1/groups/" + group + "/members/nobody").status, 404u);
  EXPECT_EQ(rig.request(verb::delete_, member).status, 204u);
  EXPECT_EQ(rig.request(verb::delete_, member).status, 404u);
  EXPECT_EQ(rig.get("/api/v1/groups/nothing/members").status, 404u);
}

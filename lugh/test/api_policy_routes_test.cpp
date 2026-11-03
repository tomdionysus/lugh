//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/api/policy_routes.h"
#include "lugh/test/fixtures/api_rig.h"

using lugh::http::verb;

TEST(PolicyRoutes, GlobalAndPerGroup) {
  ApiRig rig;
  EXPECT_EQ(rig.get("/api/v1/policies").body.at("global"), "urn:lugh:acr:mfa");

  const auto group = std::string(rig.post("/api/v1/groups", R"({"name":"admins"})").body.at("id").as_string());
  const auto set = rig.request(verb::put, "/api/v1/policies/groups/" + group, R"({"acr":"urn:lugh:acr:phr"})");
  ASSERT_EQ(set.status, 200u) << set.response->body();
  const auto groups = set.body.at("groups").as_array();
  ASSERT_EQ(groups.size(), 1u);
  EXPECT_EQ(groups[0].at("group").as_string(), group);
  EXPECT_EQ(groups[0].at("acr"), "urn:lugh:acr:phr");

  EXPECT_EQ(rig.request(verb::put, "/api/v1/policies/groups/" + group, R"({"acr":null})").body.at("groups").as_array().size(), 0u);
  EXPECT_EQ(rig.request(verb::put, "/api/v1/policies/global", R"({"acr":"urn:lugh:acr:pwd"})").body.at("global"), "urn:lugh:acr:pwd");
}

TEST(PolicyRoutes, OnlyTheThreeLevels) {
  ApiRig rig;
  EXPECT_EQ(rig.request(verb::put, "/api/v1/policies/global", R"({"acr":null})").status, 400u);
  EXPECT_EQ(rig.request(verb::put, "/api/v1/policies/global", R"({"acr":"mfa"})").status, 400u);
  EXPECT_EQ(rig.request(verb::put, "/api/v1/policies/global", R"({})").status, 400u);
  EXPECT_EQ(rig.request(verb::put, "/api/v1/policies/groups/nothing", R"({"acr":"urn:lugh:acr:mfa"})").status, 404u);
  EXPECT_EQ(run(rig.policies->global()), lugh::authn::Assurance::mfa);
}

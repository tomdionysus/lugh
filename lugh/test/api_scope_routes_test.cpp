//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/api_rig.h"

using lugh::http::field;
using lugh::http::verb;

namespace {

class ScopeRoutesTest : public ::testing::Test {
 protected:
  std::string made_group(const std::string& name) {
    const auto made = rig.post("/api/v1/groups", R"({"name":")" + name + R"("})");
    EXPECT_EQ(made.status, 201u);
    return std::string(made.body.at("id").as_string());
  }

  ApiRig rig;
};

}  // namespace

TEST_F(ScopeRoutesTest, TheKnownScopes) {
  const auto known = rig.get("/api/v1/scopes");
  ASSERT_EQ(known.status, 200u) << known.response->body();
  EXPECT_EQ(known.body.at("lugh").as_array().size(), lugh::scopes::lugh_scopes().size());
  EXPECT_EQ(known.body.at("oidc").as_array().front(), "openid");
  EXPECT_EQ(rig.request(verb::get, "/api/v1/scopes", "", {}, "Bearer reader").status, 200u);
}

TEST_F(ScopeRoutesTest, AGroupsScopesWithETags) {
  const auto id = made_group("staff");
  const auto path = "/api/v1/groups/" + id + "/scopes";

  const auto none = rig.get(path);
  ASSERT_EQ(none.status, 200u) << none.response->body();
  EXPECT_TRUE(none.body.at("scopes").as_array().empty());
  EXPECT_EQ(none.header(field::etag), "\"0\"");

  EXPECT_EQ(rig.request(verb::put, path, R"({"scopes":["openid"]})").status, 428u);
  const auto set = rig.request(verb::put, path, R"({"scopes":["toms:dns","openid","toms:dns"]})", {{field::if_match, "\"0\""}});
  ASSERT_EQ(set.status, 200u) << set.response->body();
  EXPECT_EQ(set.body.at("scopes"), (boost::json::array{"openid", "toms:dns"}));
  EXPECT_EQ(set.header(field::etag), "\"1\"");

  const auto stale = rig.request(verb::put, path, R"({"scopes":[]})", {{field::if_match, "\"0\""}});
  EXPECT_EQ(stale.status, 412u);
  EXPECT_EQ(stale.error(), "changed");
  EXPECT_EQ(rig.request(verb::put, path, R"({"scopes":[]})", {{field::if_match, "*"}}).header(field::etag), "\"2\"");
}

TEST_F(ScopeRoutesTest, RefusesWhatCannotBeGranted) {
  const auto id = made_group("staff");
  const auto path = "/api/v1/groups/" + id + "/scopes";
  const std::vector<std::pair<field, std::string>> any{{field::if_match, "*"}};
  EXPECT_EQ(rig.request(verb::put, path, R"({"scopes":["lugh:everything"]})", any).error(), "invalid");
  EXPECT_EQ(rig.request(verb::put, path, R"({"scopes":"openid"})", any).status, 400u);
  EXPECT_EQ(rig.request(verb::put, path, R"({"scopes":["openid",7]})", any).status, 400u);
  EXPECT_EQ(rig.request(verb::put, path, R"({"scope":["openid"]})", any).status, 400u);
  EXPECT_EQ(rig.request(verb::put, "/api/v1/groups/nobody/scopes", R"({"scopes":[]})", any).status, 404u);
  EXPECT_EQ(rig.get("/api/v1/groups/nobody/scopes").status, 404u);
}

// Who holds which scope is policy: reading it needs directory.read, changing it policies.write.
TEST_F(ScopeRoutesTest, ChangingGrantsNeedsPoliciesWrite) {
  const auto id = made_group("staff");
  const auto path = "/api/v1/groups/" + id + "/scopes";
  EXPECT_EQ(rig.request(verb::get, path, "", {}, "Bearer reader").status, 200u);
  EXPECT_EQ(rig.request(verb::put, path, R"({"scopes":[]})", {{field::if_match, "*"}}, "Bearer reader").status, 403u);
  EXPECT_EQ(rig.request(verb::get, path, "", {}, "").status, 401u);
}

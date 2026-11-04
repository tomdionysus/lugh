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

const std::string kWeb = R"({
  "name": "blackraven-admin",
  "kind": "web",
  "client_authentication": "private_key_jwt",
  "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]},
  "redirect_uris": ["https://admin.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile"],
  "audiences": ["lugh"],
  "acr": "urn:lugh:acr:mfa",
  "lifetimes": {"access_token": 600}
})";

class AppRoutesTest : public ::testing::Test {
 protected:
  ApiRig rig;
};

}  // namespace

TEST_F(AppRoutesTest, RegisterThenRead) {
  const auto made = rig.post("/api/v1/apps", kWeb);
  ASSERT_EQ(made.status, 201u) << made.response->body();
  const auto id = std::string(made.body.at("client_id").as_string());
  EXPECT_EQ(made.header(field::location), "/api/v1/apps/" + id);
  EXPECT_EQ(made.header(field::etag), "\"1\"");
  EXPECT_EQ(made.body.at("kind"), "web");
  EXPECT_EQ(made.body.at("grant_types"), (boost::json::array{"authorization_code", "refresh_token"}));
  EXPECT_EQ(made.body.at("jwks").at("keys").as_array().size(), 1u);
  EXPECT_EQ(made.body.at("lifetimes").at("access_token"), 600);
  EXPECT_EQ(made.body.at("lifetimes").at("id_token"), 300);
  EXPECT_EQ(made.body.at("enabled"), true);
  EXPECT_FALSE(made.body.as_object().contains("client_secret"));

  const auto read = rig.get("/api/v1/apps/" + id);
  ASSERT_EQ(read.status, 200u);
  EXPECT_EQ(read.body.at("name"), "blackraven-admin");
  EXPECT_EQ(read.body.at("acr"), "urn:lugh:acr:mfa");
  EXPECT_EQ(rig.get("/api/v1/apps").body.at("apps").as_array().size(), 1u);
  EXPECT_EQ(rig.get("/api/v1/apps/app_nobody").status, 404u);
}

// The secret leaves Lugh once, in the answer to whoever made it; nothing shows it again.
TEST_F(AppRoutesTest, ASecretIsShownOnce) {
  const auto made = rig.post("/api/v1/apps", R"({"name":"hub","kind":"service","client_authentication":"client_secret_basic",
                                                   "grant_types":["client_credentials"],"client_scopes":["lugh:directory.read"]})");
  ASSERT_EQ(made.status, 201u) << made.response->body();
  const auto secret = std::string(made.body.at("client_secret").as_string());
  EXPECT_EQ(secret.size(), 43u);
  const auto id = std::string(made.body.at("client_id").as_string());
  const auto read = rig.get("/api/v1/apps/" + id);
  EXPECT_EQ(read.response->body().find(secret), std::string::npos);
  EXPECT_FALSE(read.body.as_object().contains("client_secret"));

  const auto rotated = rig.post("/api/v1/apps/" + id + "/secret", "");
  ASSERT_EQ(rotated.status, 201u) << rotated.response->body();
  EXPECT_NE(std::string(rotated.body.at("client_secret").as_string()), secret);
  EXPECT_EQ(rotated.body.at("previous_secret_expires_at"), "2026-10-19T00:00:00Z");
}

TEST_F(AppRoutesTest, RefusesWhatIsNotAnApplication) {
  for (const auto* body : {R"({"name":"x","kind":"desktop"})", R"({"name":"x","kind":"web","colour":"red"})", R"({"name":7})",
                           R"({"name":"x","kind":"web","grant_types":["password"]})", R"({"name":"x","kind":"web","grant_types":["implicit"]})",
                           R"({"name":"x","kind":"spa","grant_types":["authorization_code"],"redirect_uris":["http://a.example.com/cb"]})",
                           R"({"name":"x","kind":"api","scope_prefix":"lugh"})", "[]"}) {
    const auto answer = rig.post("/api/v1/apps", body);
    EXPECT_EQ(answer.status, 400u) << body;
    EXPECT_EQ(answer.error(), "invalid") << body;
  }
  // Client secrets are off unless policy allows them; this rig allows them, as a test of the
  // rest. AppsTest.ClientSecretsOnlyWherePolicyAllows covers the refusal.
  EXPECT_EQ(rig.get("/api/v1/apps").body.at("apps").as_array().size(), 0u);
}

TEST_F(AppRoutesTest, UpdatesNeedTheCurrentETagAndKeepWhatNeverChanges) {
  const auto id = std::string(rig.post("/api/v1/apps", kWeb).body.at("client_id").as_string());
  const auto path = "/api/v1/apps/" + id;

  EXPECT_EQ(rig.request(verb::patch, path, R"({"name":"admin"})").status, 428u);
  const auto changed = rig.request(verb::patch, path, R"({"name":"admin","enabled":false,"first_party":true})", {{field::if_match, "\"1\""}});
  ASSERT_EQ(changed.status, 200u) << changed.response->body();
  EXPECT_EQ(changed.body.at("name"), "admin");
  EXPECT_EQ(changed.body.at("enabled"), false);
  EXPECT_EQ(changed.header(field::etag), "\"2\"");
  EXPECT_EQ(rig.request(verb::patch, path, R"({"name":"b"})", {{field::if_match, "\"1\""}}).status, 412u);
  EXPECT_EQ(rig.request(verb::patch, path, R"({"kind":"spa"})", {{field::if_match, "*"}}).status, 400u);
  EXPECT_EQ(rig.request(verb::patch, path, R"({"redirect_uris":[]})", {{field::if_match, "*"}}).status, 400u);

  EXPECT_EQ(rig.request(verb::delete_, path).status, 428u);
  EXPECT_EQ(rig.request(verb::delete_, path, "", {{field::if_match, "\"2\""}}).status, 204u);
  EXPECT_EQ(rig.get(path).status, 404u);
}

TEST_F(AppRoutesTest, AccessAndRoles) {
  const auto id = std::string(rig.post("/api/v1/apps", kWeb).body.at("client_id").as_string());
  const auto group = std::string(rig.post("/api/v1/groups", R"({"name":"staff"})").body.at("id").as_string());

  const auto allowed = rig.request(verb::put, "/api/v1/apps/" + id + "/access/" + group);
  ASSERT_EQ(allowed.status, 200u) << allowed.response->body();
  EXPECT_EQ(allowed.body.at("access"), (boost::json::array{boost::json::string(group)}));
  EXPECT_EQ(rig.request(verb::put, "/api/v1/apps/" + id + "/access/nobody").status, 404u);

  const auto mapped = rig.request(verb::put, "/api/v1/apps/" + id + "/roles/" + group, R"({"roles":["operator"]})");
  ASSERT_EQ(mapped.status, 200u) << mapped.response->body();
  EXPECT_EQ(mapped.body.at("roles").at(group), (boost::json::array{"operator"}));
  EXPECT_EQ(rig.request(verb::put, "/api/v1/apps/" + id + "/roles/" + group, R"({"roles":"operator"})").status, 400u);

  const auto removed = rig.request(verb::delete_, "/api/v1/apps/" + id + "/access/" + group);
  EXPECT_TRUE(removed.body.at("access").as_array().empty());
}

// Reading applications is directory.read; changing them is apps.write.
TEST_F(AppRoutesTest, ChangingApplicationsNeedsAppsWrite) {
  EXPECT_EQ(rig.request(verb::get, "/api/v1/apps", "", {}, "Bearer reader").status, 200u);
  EXPECT_EQ(rig.request(verb::post, "/api/v1/apps", kWeb, {}, "Bearer reader").status, 403u);
  EXPECT_EQ(rig.request(verb::get, "/api/v1/apps", "", {}, "").status, 401u);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/api_rig.h"

using lugh::http::verb;

namespace {

void open(ApiRig& rig) {
  EXPECT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { rig.keys->open(kTestDeadline, executor, done); }).ok);
}

}  // namespace

TEST(KeyRoutes, ListNeverShowsAPrivateKey) {
  ApiRig rig;
  open(rig);
  const auto listed = rig.get("/api/v1/keys");
  ASSERT_EQ(listed.status, 200u) << listed.response->body();
  const auto keys = listed.body.at("keys").as_array();
  ASSERT_EQ(keys.size(), 2u);
  for (const auto& key : keys) {
    EXPECT_EQ(key.as_object().size(), 5u);
    EXPECT_TRUE(key.at("retired_at").is_null());
  }
}

TEST(KeyRoutes, RotateNeedsKeysWrite) {
  ApiRig rig;
  open(rig);
  const auto made = rig.post("/api/v1/keys/rotate", R"({"algorithm":"EdDSA"})");
  ASSERT_EQ(made.status, 201u) << made.response->body();
  EXPECT_EQ(made.body.at("algorithm"), "EdDSA");
  EXPECT_EQ(made.body.at("signing_from"), "2026-10-18T01:00:00Z");
  EXPECT_EQ(rig.get("/api/v1/keys").body.at("keys").as_array().size(), 3u);

  EXPECT_EQ(rig.post("/api/v1/keys/rotate", R"({"algorithm":"RS256"})").status, 400u);
  EXPECT_EQ(rig.post("/api/v1/keys/rotate", R"({})").status, 400u);
  EXPECT_EQ(rig.request(verb::post, "/api/v1/keys/rotate", R"({"algorithm":"ES256"})", {}, "Bearer reader").status, 403u);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/api/audit_routes.h"
#include "lugh/test/fixtures/api_rig.h"

TEST(AuditRoutes, PagesAndTheirEnd) {
  ApiRig rig;
  for (int i = 0; i < 5; ++i) rig.made_user("user" + std::to_string(i));

  const auto first = rig.get("/api/v1/audit?limit=2");
  ASSERT_EQ(first.status, 200u);
  const auto& entries = first.body.at("entries").as_array();
  ASSERT_EQ(entries.size(), 2u);
  EXPECT_EQ(entries[0].at("sequence"), 1);
  EXPECT_EQ(entries[0].at("action"), "user.create");
  EXPECT_EQ(entries[0].at("actor"), ApiRig::kAdministrator);
  EXPECT_EQ(entries[1].at("previous"), entries[0].at("hash"));
  EXPECT_EQ(first.body.at("next"), 3);

  const auto last = rig.get("/api/v1/audit?from=5&limit=2");
  EXPECT_EQ(last.body.at("entries").as_array().size(), 1u);
  EXPECT_TRUE(last.body.at("next").is_null());

  EXPECT_EQ(rig.get("/api/v1/audit?limit=0").status, 400u);
  EXPECT_EQ(rig.get("/api/v1/audit?limit=1001").status, 400u);
  EXPECT_EQ(rig.get("/api/v1/audit?from=x").status, 400u);
}

TEST(AuditRoutes, Verify) {
  ApiRig rig;
  rig.made_user("alice");
  const auto intact = rig.get("/api/v1/audit/verify");
  EXPECT_EQ(intact.body.at("intact"), true);
  EXPECT_EQ(intact.body.at("entries"), 1);

  rig.store->remove_now("audit", lugh::audit::AuditLog::key(1));
  const auto broken = rig.get("/api/v1/audit/verify");
  EXPECT_EQ(broken.body.at("intact"), false);
  EXPECT_EQ(broken.body.at("problem"), "audit entry 1 is missing");
}

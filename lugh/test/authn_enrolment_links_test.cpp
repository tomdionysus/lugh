//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/authn/enrolment_links.h"
#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using lugh::Secret;
using lugh::text_secret;
using lugh::authn::EnrolmentLinks;

namespace {

class EnrolmentLinksTest : public ::testing::Test {
 protected:
  void SetUp() override { alice = rig.person("alice"); }

  AuthnRig rig;
  EnrolmentLinks& links = *rig.links;
  lugh::directory::User alice;
};

}  // namespace

TEST_F(EnrolmentLinksTest, ALinkWorksOnce) {
  const auto token = run(links.issue(rig.admin, alice.id));
  ASSERT_TRUE(token.ok()) << token.message;
  EXPECT_EQ(token.value.size(), 43u);

  EXPECT_EQ(run(links.peek(copy_of(token.value))).value, alice.id);
  EXPECT_EQ(run(links.peek(copy_of(token.value))).value, alice.id);
  const auto spent = run(links.spend(copy_of(token.value), {"anonymous", "192.0.2.1"}));
  ASSERT_TRUE(spent.ok());
  EXPECT_EQ(spent.value, alice.id);
  EXPECT_EQ(run(links.spend(copy_of(token.value), {"anonymous", "192.0.2.1"})).fault, Fault::not_found);
  EXPECT_EQ(run(links.peek(copy_of(token.value))).fault, Fault::not_found);
  EXPECT_TRUE(rig.audited("enrolment.issue"));
  EXPECT_TRUE(rig.audited("enrolment.redeem"));
}

TEST_F(EnrolmentLinksTest, TheTableHoldsNoToken) {
  const auto token = run(links.issue(rig.admin, alice.id)).value;
  for (const auto& record : rig.store->list_now(EnrolmentLinks::kTable)) {
    EXPECT_EQ(record.key.find(lugh::secret_text(token)), std::string::npos);
    const std::string value(record.value.begin(), record.value.end());
    EXPECT_EQ(value.find(lugh::secret_text(token)), std::string::npos);
  }
}

TEST_F(EnrolmentLinksTest, ALinkExpires) {
  const auto token = run(links.issue(rig.admin, alice.id)).value;
  rig.advance(std::chrono::hours(72) - std::chrono::seconds(1));
  EXPECT_TRUE(run(links.peek(copy_of(token))).ok());
  rig.advance(std::chrono::seconds(1));
  EXPECT_EQ(run(links.peek(copy_of(token))).fault, Fault::not_found);
  EXPECT_EQ(run(links.spend(copy_of(token), {"anonymous", ""})).fault, Fault::not_found);
}

TEST_F(EnrolmentLinksTest, ANewLinkEndsTheOld) {
  const auto first = run(links.issue(rig.admin, alice.id)).value;
  const auto second = run(links.issue(rig.admin, alice.id)).value;
  EXPECT_EQ(run(links.peek(copy_of(first))).fault, Fault::not_found);
  EXPECT_TRUE(run(links.peek(copy_of(second))).ok());
}

TEST_F(EnrolmentLinksTest, OnlyForAPersonWhoIsNotEnrolled) {
  const auto service = run(rig.directory->create_user(rig.admin, {lugh::directory::Kind::service, "backup", "", ""})).value;
  EXPECT_EQ(run(links.issue(rig.admin, service.id)).fault, Fault::refused);
  EXPECT_EQ(run(links.issue(rig.admin, "nobody")).fault, Fault::not_found);

  run(rig.directory->enrolled_set(rig.admin, alice.id, true));
  EXPECT_EQ(run(links.issue(rig.admin, alice.id)).fault, Fault::refused);
  run(rig.directory->enrolled_set(rig.admin, alice.id, false));
  run(rig.directory->disable_user(rig.admin, alice.id, true));
  EXPECT_EQ(run(links.issue(rig.admin, alice.id)).fault, Fault::refused);
}

TEST_F(EnrolmentLinksTest, AnythingElseIsNoLink) {
  run(links.issue(rig.admin, alice.id));
  EXPECT_EQ(run(links.peek(text_secret(""))).fault, Fault::not_found);
  EXPECT_EQ(run(links.peek(text_secret(std::string(43, 'A')))).fault, Fault::not_found);
  EXPECT_EQ(run(links.peek(text_secret(std::string(42, 'A') + "!"))).fault, Fault::not_found);
}

TEST_F(EnrolmentLinksTest, RecordsRoundTrip) {
  const EnrolmentLinks::Link link{"u1", 5, 10};
  const auto back = EnrolmentLinks::decode(EnrolmentLinks::encode(link));
  ASSERT_TRUE(back);
  EXPECT_EQ(back->user_id, "u1");
  EXPECT_EQ(back->expires, 10u);
  EXPECT_FALSE(EnrolmentLinks::decode(EnrolmentLinks::encode(EnrolmentLinks::Link{"", 5, 10})));
}

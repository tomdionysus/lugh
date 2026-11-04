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
  std::shared_ptr<EnrolmentLinks>& links = rig.links;
  lugh::directory::User alice;
};

}  // namespace

TEST_F(EnrolmentLinksTest, ALinkWorksOnce) {
  const auto token =
      wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) { links->issue(rig.admin, alice.id, kTestDeadline, executor, done); });
  ASSERT_TRUE(token.ok()) << token.message;
  EXPECT_EQ(token.value.size(), 43u);

  EXPECT_EQ(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(token.value), kTestDeadline, executor, done); }).value,
      alice.id);
  EXPECT_EQ(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(token.value), kTestDeadline, executor, done); }).value,
      alice.id);
  const auto spent = wait_for<lugh::Outcome<std::string>>(
      [&](lugh::Executor executor, auto done) { links->spend(copy_of(token.value), {"anonymous", "192.0.2.1"}, kTestDeadline, executor, done); });
  ASSERT_TRUE(spent.ok());
  EXPECT_EQ(spent.value, alice.id);
  EXPECT_EQ(wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) {
              links->spend(copy_of(token.value), {"anonymous", "192.0.2.1"}, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
  EXPECT_EQ(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(token.value), kTestDeadline, executor, done); }).fault,
      Fault::not_found);
  EXPECT_TRUE(rig.audited("enrolment.issue"));
  EXPECT_TRUE(rig.audited("enrolment.redeem"));
}

TEST_F(EnrolmentLinksTest, TheTableHoldsNoToken) {
  const auto token = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                       links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  for (const auto& record : rig.store->list_now(EnrolmentLinks::kTable)) {
    EXPECT_EQ(record.key.find(lugh::secret_text(token)), std::string::npos);
    const std::string value(record.value.begin(), record.value.end());
    EXPECT_EQ(value.find(lugh::secret_text(token)), std::string::npos);
  }
}

TEST_F(EnrolmentLinksTest, ALinkExpires) {
  const auto token = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                       links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  rig.advance(std::chrono::hours(72) - std::chrono::seconds(1));
  EXPECT_TRUE(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(token), kTestDeadline, executor, done); }).ok());
  rig.advance(std::chrono::seconds(1));
  EXPECT_EQ(wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(token), kTestDeadline, executor, done); }).fault,
            Fault::not_found);
  EXPECT_EQ(wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) {
              links->spend(copy_of(token), {"anonymous", ""}, kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
}

TEST_F(EnrolmentLinksTest, ANewLinkEndsTheOld) {
  const auto first = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                       links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                     }).value;
  const auto second = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                        links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                      }).value;
  EXPECT_EQ(wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(first), kTestDeadline, executor, done); }).fault,
            Fault::not_found);
  EXPECT_TRUE(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(copy_of(second), kTestDeadline, executor, done); }).ok());
}

TEST_F(EnrolmentLinksTest, OnlyForAPersonWhoIsNotEnrolled) {
  const auto service = wait_for<lugh::Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                         rig.directory->create_user(rig.admin, {lugh::directory::Kind::service, "backup", "", ""}, kTestDeadline, executor, done);
                       }).value;
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
              links->issue(rig.admin, service.id, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
              links->issue(rig.admin, "nobody", kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);

  wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->enrolled_set(rig.admin, alice.id, true, kTestDeadline, executor, done); });
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
              links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
  wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->enrolled_set(rig.admin, alice.id, false, kTestDeadline, executor, done); });
  wait_for<lugh::Outcome<lugh::directory::User>>(
      [&](lugh::Executor executor, auto done) { rig.directory->disable_user(rig.admin, alice.id, true, std::nullopt, kTestDeadline, executor, done); });
  EXPECT_EQ(wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
              links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
}

TEST_F(EnrolmentLinksTest, AnythingElseIsNoLink) {
  wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) { links->issue(rig.admin, alice.id, kTestDeadline, executor, done); });
  EXPECT_EQ(
      wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) { links->peek(text_secret(""), kTestDeadline, executor, done); }).fault,
      Fault::not_found);
  EXPECT_EQ(wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) {
              links->peek(text_secret(std::string(43, 'A')), kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
  EXPECT_EQ(wait_for<lugh::Outcome<std::string>>([&](lugh::Executor executor, auto done) {
              links->peek(text_secret(std::string(42, 'A') + "!"), kTestDeadline, executor, done);
            }).fault,
            Fault::not_found);
}

TEST_F(EnrolmentLinksTest, RecordsRoundTrip) {
  const EnrolmentLinks::Link link{"u1", 5, 10};
  const auto back = EnrolmentLinks::decode(EnrolmentLinks::encode(link));
  ASSERT_TRUE(back);
  EXPECT_EQ(back->user_id, "u1");
  EXPECT_EQ(back->expires, 10u);
  EXPECT_FALSE(EnrolmentLinks::decode(EnrolmentLinks::encode(EnrolmentLinks::Link{"", 5, 10})));
}

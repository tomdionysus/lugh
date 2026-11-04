//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/session/sessions.h"
#include "lugh/test/fixtures/authn_rig.h"

using lugh::Outcome;
using lugh::Status;
using lugh::authn::Assurance;
using lugh::session::Session;
using lugh::session::Sessions;
using std::chrono::hours;

namespace {

class SessionsTest : public ::testing::Test {
 protected:
  std::shared_ptr<Sessions> opened() {
    auto made = std::make_shared<Sessions>(rig.store, rig.wall, rig.directory, rig.grants, rig.audit, Sessions::Settings{});
    EXPECT_TRUE(wait_for<Status>([&](lugh::Executor executor, auto done) { made->open(kTestDeadline, executor, done); }).ok);
    return made;
  }

  Sessions::Created create(const std::shared_ptr<Sessions>& in, const std::string& user_id) {
    auto made = wait_for<Outcome<Sessions::Created>>(
        [&](lugh::Executor executor, auto done) { in->create(rig.admin, user_id, Assurance::mfa, {"pwd", "otp"}, kTestDeadline, executor, done); });
    EXPECT_TRUE(made.ok()) << made.message;
    return std::move(made.value);
  }

  void refresh(const std::shared_ptr<Sessions>& in) {
    EXPECT_TRUE(wait_for<Status>([&](lugh::Executor executor, auto done) { in->refresh(kTestDeadline, executor, done); }).ok);
  }

  std::string handle(const Sessions::Created& made) { return std::string(lugh::secret_text(made.handle)); }

  AuthnRig rig;
};

}  // namespace

TEST_F(SessionsTest, AHandleOpensItsSessionAndOnlyThatIsStored) {
  const auto sessions = opened();
  const auto alice = rig.person("alice");
  const auto made = create(sessions, alice.id);
  EXPECT_EQ(handle(made).size(), 43u);
  EXPECT_EQ(made.session.key, Sessions::key_of(handle(made)));
  EXPECT_EQ(made.session.acr, Assurance::mfa);
  EXPECT_EQ(made.session.amr, (std::vector<std::string>{"pwd", "otp"}));
  EXPECT_NE(made.session.sid, made.session.key);

  const auto found = sessions->find(handle(made));
  ASSERT_TRUE(found);
  EXPECT_EQ(found->user_id, alice.id);
  EXPECT_FALSE(sessions->find(handle(made) + "x"));
  EXPECT_FALSE(sessions->find(""));
  // The store holds the hash, never the handle.
  EXPECT_FALSE(rig.store->get_now(Sessions::kTable, handle(made)));
  EXPECT_TRUE(rig.store->get_now(Sessions::kTable, made.session.key));
}

TEST_F(SessionsTest, TheCsrfTokenIsTheSessionsOwn) {
  const auto sessions = opened();
  const auto alice = rig.person("alice");
  const auto one = create(sessions, alice.id);
  const auto two = create(sessions, alice.id);
  const auto token = Sessions::csrf_token(one.session);
  EXPECT_TRUE(Sessions::csrf_ok(one.session, token));
  EXPECT_FALSE(Sessions::csrf_ok(two.session, token));
  EXPECT_FALSE(Sessions::csrf_ok(one.session, ""));
}

// the maintainer, 2026-11-04: 24 hours idle, 30 days at most.
TEST_F(SessionsTest, IdleAndAbsoluteLifetimes) {
  const auto sessions = opened();
  const auto alice = rig.person("alice");
  const auto idle = create(sessions, alice.id);
  rig.advance(hours(23));
  EXPECT_TRUE(sessions->find(handle(idle)));
  rig.advance(hours(23));
  EXPECT_TRUE(sessions->find(handle(idle)));
  rig.advance(hours(25));
  EXPECT_FALSE(sessions->find(handle(idle)));

  // Used every 23 hours, so never idle: it still ends at 30 days.
  const auto busy = create(sessions, alice.id);
  int elapsed = 0;
  while (elapsed + 23 < 720) {
    rig.advance(hours(23));
    elapsed += 23;
    ASSERT_TRUE(sessions->find(handle(busy))) << elapsed;
  }
  rig.advance(hours(720 - elapsed) + std::chrono::minutes(1));
  EXPECT_FALSE(sessions->find(handle(busy)));
}

TEST_F(SessionsTest, SessionsSurviveARestart) {
  const auto alice = rig.person("alice");
  const auto made = create(opened(), alice.id);
  const auto again = opened();
  const auto found = again->find(handle(made));
  ASSERT_TRUE(found);
  EXPECT_EQ(found->sid, made.session.sid);
  EXPECT_TRUE(Sessions::csrf_ok(*found, Sessions::csrf_token(made.session)));
}

TEST_F(SessionsTest, SigningOutEndsItAtOnce) {
  const auto sessions = opened();
  const auto alice = rig.person("alice");
  const auto made = create(sessions, alice.id);
  EXPECT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) { sessions->end(rig.admin, handle(made), kTestDeadline, executor, done); }).ok());
  EXPECT_FALSE(sessions->find(handle(made)));
  EXPECT_FALSE(opened()->find(handle(made)));
  EXPECT_TRUE(rig.audited("session.end"));
  // Ending one that is not there is no error.
  EXPECT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) { sessions->end(rig.admin, handle(made), kTestDeadline, executor, done); }).ok());
}

// The scopes a session carries follow its user's groups at the next refresh, and a disabled or
// removed user's sessions end then.
TEST_F(SessionsTest, RefreshFollowsTheDirectory) {
  const auto sessions = opened();
  const auto alice = rig.person("alice");
  const auto bob = rig.person("bob");
  const auto staff = wait_for<Outcome<lugh::directory::Group>>([&](lugh::Executor executor, auto done) {
                       rig.directory->create_group(rig.admin, "staff", "", kTestDeadline, executor, done);
                     }).value;
  ASSERT_TRUE(wait_for<Outcome<lugh::scopes::Granted>>([&](lugh::Executor executor, auto done) {
                rig.grants->group_set(rig.admin, staff.id, {"lugh:audit.read"}, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  ASSERT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->add_member(rig.admin, staff.id, alice.id, kTestDeadline, executor, done);
              }).ok());

  const auto made = create(sessions, alice.id);
  EXPECT_EQ(made.session.scopes, std::vector<std::string>{"lugh:audit.read"});
  const auto other = create(sessions, bob.id);

  ASSERT_TRUE(wait_for<Outcome<>>([&](lugh::Executor executor, auto done) {
                rig.directory->remove_member(rig.admin, staff.id, alice.id, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(sessions->find(handle(made))->scopes, std::vector<std::string>{"lugh:audit.read"});
  refresh(sessions);
  EXPECT_TRUE(sessions->find(handle(made))->scopes.empty());
  // And the store agrees, after a restart.
  EXPECT_TRUE(opened()->find(handle(made))->scopes.empty());

  ASSERT_TRUE(wait_for<Outcome<lugh::directory::User>>([&](lugh::Executor executor, auto done) {
                rig.directory->disable_user(rig.admin, bob.id, true, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_TRUE(sessions->find(handle(other)));
  refresh(sessions);
  EXPECT_FALSE(sessions->find(handle(other)));
  EXPECT_TRUE(sessions->find(handle(made)));
}

TEST(SessionRecord, RoundTripsAndRefusesWhatEncodingWouldNotMake) {
  Session session;
  session.user_id = "u";
  session.sid = "s";
  session.acr = Assurance::mfa;
  session.amr = {"pwd", "otp"};
  session.auth_time = 1;
  session.created = 2;
  session.last_seen = 3;
  session.csrf = lugh::SecureBuffer(32, 7);
  session.scopes = {"openid"};
  session.apps = {"client-a", "client-b"};
  const auto bytes = Sessions::encode(session);
  const auto back = Sessions::decode(bytes);
  ASSERT_TRUE(back);
  EXPECT_EQ(back->amr, session.amr);
  EXPECT_EQ(back->csrf, session.csrf);
  EXPECT_EQ(back->scopes, session.scopes);
  EXPECT_EQ(back->apps, session.apps);

  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(Sessions::decode(longer));
  auto format = bytes;
  format[0] = 3;
  EXPECT_FALSE(Sessions::decode(format));
}

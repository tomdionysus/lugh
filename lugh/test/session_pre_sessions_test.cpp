//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/session/pre_sessions.h"

using lugh::session::PreSession;
using lugh::session::PreSessions;
using std::chrono::minutes;

namespace {

PreSession at(const std::string& user_id) {
  PreSession pre;
  pre.sign_in.user_id = user_id;
  pre.sign_in.stage = lugh::authn::SignIn::Stage::second_factor;
  return pre;
}

}  // namespace

TEST(PreSessions, HandlesAndTheirTokens) {
  dannan::test::SteppedTime time;
  PreSessions pre(time, minutes(15));
  const auto handle = PreSessions::new_handle();
  EXPECT_TRUE(PreSessions::handle_ok(handle));
  EXPECT_NE(PreSessions::new_handle(), handle);
  EXPECT_FALSE(PreSessions::handle_ok("short"));
  EXPECT_FALSE(PreSessions::handle_ok(handle + "A"));

  const auto token = pre.csrf_token(handle);
  EXPECT_TRUE(pre.csrf_ok(handle, token));
  EXPECT_FALSE(pre.csrf_ok(PreSessions::new_handle(), token));
  EXPECT_FALSE(pre.csrf_ok(handle, token + "x"));
  // Another process's key makes other tokens: a token is no good anywhere but where it was made.
  PreSessions other(time, minutes(15));
  EXPECT_FALSE(other.csrf_ok(handle, token));
}

TEST(PreSessions, HeldForTheLifetimeOfASignIn) {
  dannan::test::SteppedTime time;
  PreSessions pre(time, minutes(15));
  const auto handle = PreSessions::new_handle();
  EXPECT_FALSE(pre.find(handle));
  pre.put(handle, at("u1"));
  EXPECT_EQ(pre.find(handle)->sign_in.user_id, "u1");
  // A later step does not restart the clock.
  time.advance(minutes(10));
  pre.put(handle, at("u1"));
  time.advance(minutes(6));
  EXPECT_FALSE(pre.find(handle));

  const auto another = PreSessions::new_handle();
  pre.put(another, at("u2"));
  pre.end(another);
  EXPECT_FALSE(pre.find(another));
  pre.put("not a handle", at("u3"));
  EXPECT_FALSE(pre.find("not a handle"));
}

TEST(PreSessions, PastTheLimitTheOldestGoes) {
  dannan::test::SteppedTime time;
  PreSessions pre(time, minutes(15), 3);
  std::vector<std::string> handles;
  for (int i = 0; i < 4; ++i) {
    handles.push_back(PreSessions::new_handle());
    pre.put(handles.back(), at("u" + std::to_string(i)));
    time.advance(std::chrono::seconds(1));
  }
  EXPECT_FALSE(pre.find(handles[0]));
  for (int i = 1; i < 4; ++i) EXPECT_TRUE(pre.find(handles[static_cast<std::size_t>(i)])) << i;
}

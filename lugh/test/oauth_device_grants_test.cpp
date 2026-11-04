//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/oauth/device_grants.h"

using lugh::oauth::CodeGrant;
using lugh::oauth::DeviceGrants;
using Poll = DeviceGrants::Poll;
using std::chrono::seconds;

// RFC 8628 section 6.1: eight letters from twenty consonants, shown as XXXX-XXXX, typed any way.
TEST(DeviceGrants, UserCodes) {
  dannan::test::SteppedTime time;
  DeviceGrants devices(time);
  const auto started = devices.start("app_tv", {"openid"});
  ASSERT_EQ(started.user_code.size(), 9u);
  EXPECT_EQ(started.user_code[4], '-');
  for (const char c : started.user_code) EXPECT_TRUE(c == '-' || DeviceGrants::kAlphabet.find(c) != std::string_view::npos) << c;
  EXPECT_NE(started.device_code, started.user_code);

  auto typed = started.user_code;
  for (auto& c : typed) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  std::erase(typed, '-');
  ASSERT_TRUE(devices.find(typed));
  EXPECT_EQ(devices.find(typed)->client_id, "app_tv");
  EXPECT_FALSE(DeviceGrants::normal("AEIO-UBCD"));
  EXPECT_FALSE(DeviceGrants::normal("BCDF"));
  EXPECT_FALSE(devices.find("BCDF-GHJK"));
}

TEST(DeviceGrants, PollingUntilAnswered) {
  dannan::test::SteppedTime time;
  DeviceGrants devices(time);
  const auto started = devices.start("app_tv", {"openid"});
  EXPECT_EQ(devices.poll(started.device_code, "app_tv").state, Poll::pending);
  // Too soon: slow_down, and the interval grows to ten seconds.
  EXPECT_EQ(devices.poll(started.device_code, "app_tv").state, Poll::slow_down);
  time.advance(seconds(6));
  EXPECT_EQ(devices.poll(started.device_code, "app_tv").state, Poll::slow_down);
  time.advance(seconds(16));
  EXPECT_EQ(devices.poll(started.device_code, "app_tv").state, Poll::pending);
  // Another client's poll for it learns nothing.
  EXPECT_EQ(devices.poll(started.device_code, "app_other").state, Poll::unknown);

  CodeGrant grant;
  grant.user_id = "u1";
  EXPECT_TRUE(devices.approve(started.user_code, grant));
  EXPECT_FALSE(devices.approve(started.user_code, grant));
  EXPECT_FALSE(devices.find(started.user_code));
  time.advance(seconds(20));
  const auto approved = devices.poll(started.device_code, "app_tv");
  ASSERT_EQ(approved.state, Poll::approved);
  EXPECT_EQ(approved.grant->user_id, "u1");
  EXPECT_EQ(approved.grant->client_id, "app_tv");
  EXPECT_EQ(approved.grant->scopes, std::vector<std::string>{"openid"});
  // Answered once.
  EXPECT_EQ(devices.poll(started.device_code, "app_tv").state, Poll::unknown);
}

TEST(DeviceGrants, DeniedAndExpired) {
  dannan::test::SteppedTime time;
  DeviceGrants devices(time);
  const auto denied = devices.start("app_tv", {});
  EXPECT_TRUE(devices.deny(denied.user_code));
  EXPECT_EQ(devices.poll(denied.device_code, "app_tv").state, Poll::denied);

  const auto late = devices.start("app_tv", {});
  time.advance(seconds(601));
  EXPECT_FALSE(devices.find(late.user_code));
  EXPECT_FALSE(devices.approve(late.user_code, CodeGrant{}));
  EXPECT_EQ(devices.poll(late.device_code, "app_tv").state, Poll::expired);
}

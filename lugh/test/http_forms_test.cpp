//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/http/forms.h"

using namespace lugh::http;
using Form = std::map<std::string, std::string>;

// application/x-www-form-urlencoded, as the WHATWG URL standard has browsers write it.
TEST(Forms, ParsesWhatABrowserSends) {
  EXPECT_EQ(parse_form("login=alice&password=a+b%26c%3D"), (Form{{"login", "alice"}, {"password", "a b&c="}}));
  EXPECT_EQ(parse_form(""), Form{});
  EXPECT_EQ(parse_form("flag"), (Form{{"flag", ""}}));
  EXPECT_EQ(parse_form("a=1&&b=2"), (Form{{"a", "1"}, {"b", "2"}}));
  EXPECT_EQ(parse_form("caf%C3%A9=1"), (Form{{"caf\xc3\xa9", "1"}}));
}

TEST(Forms, RefusesWhatIsNotOneValuePerName) {
  EXPECT_FALSE(parse_form("a=1&a=2"));
  EXPECT_FALSE(parse_form("=1"));
  EXPECT_FALSE(parse_form("a=%zz"));
  EXPECT_FALSE(parse_form("a=100%"));
  EXPECT_FALSE(parse_form(std::string(kMostFormBytes + 1, 'a')));
}

TEST(Forms, Cookies) {
  HttpRequest request{verb::get, "/", 11};
  EXPECT_FALSE(cookie(request, "a"));
  request.insert(field::cookie, "a=1; b=two");
  request.insert(field::cookie, "c=3");
  EXPECT_EQ(cookie(request, "b"), "two");
  EXPECT_EQ(cookie(request, "c"), "3");
  EXPECT_FALSE(cookie(request, "ab"));
  // The same cookie twice is something a browser never sends: taken as none.
  request.insert(field::cookie, "a=other");
  EXPECT_FALSE(cookie(request, "a"));
}

TEST(Forms, HostCookies) {
  EXPECT_EQ(host_cookie("__Host-x", "v", 60), "__Host-x=v; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=60");
  EXPECT_NE(host_cookie("__Host-x", "", 0).find("Max-Age=0"), std::string::npos);
}

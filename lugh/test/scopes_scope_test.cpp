//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/scopes/scope.h"

#include <gtest/gtest.h>

using namespace lugh::scopes;
using lugh::Fault;

// RFC 6749 section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
TEST(Scope, WellFormedIsRfc6749Section3_3) {
  EXPECT_TRUE(well_formed("openid"));
  EXPECT_TRUE(well_formed("lugh:directory.read"));
  EXPECT_TRUE(well_formed("lir:sub:a/%2B/#"));
  EXPECT_TRUE(well_formed("!"));
  EXPECT_TRUE(well_formed("~"));
  EXPECT_FALSE(well_formed(""));
  EXPECT_FALSE(well_formed("two words"));
  EXPECT_FALSE(well_formed("quote\""));
  EXPECT_FALSE(well_formed("back\\slash"));
  EXPECT_FALSE(well_formed("tab\t"));
  EXPECT_FALSE(well_formed("del\x7f"));
  EXPECT_FALSE(well_formed("\xc3\xa9"));
  EXPECT_TRUE(well_formed(std::string(kMostScopeBytes, 'a')));
  EXPECT_FALSE(well_formed(std::string(kMostScopeBytes + 1, 'a')));
}

TEST(Scope, TheFourKinds) {
  for (const auto& own : lugh_scopes()) EXPECT_EQ(grantable(own).value, Kind::lugh) << own;
  for (const auto& oidc : oidc_scopes()) EXPECT_EQ(grantable(oidc).value, Kind::oidc) << oidc;
  EXPECT_EQ(grantable("toms:dns").value, Kind::application);
  EXPECT_EQ(grantable("macha:media.read").value, Kind::application);
  EXPECT_EQ(grantable("app-2:x").value, Kind::application);
  EXPECT_EQ(grantable("lir:sub:devices/{sub}/#").value, Kind::topic);
}

TEST(Scope, WhatIsNotGrantable) {
  // Lugh's prefix holds only Lugh's scopes.
  EXPECT_EQ(grantable("lugh:everything").fault, Fault::invalid);
  // A word without a prefix is an OIDC name or nothing.
  EXPECT_EQ(grantable("admin").fault, Fault::invalid);
  EXPECT_EQ(grantable("OpenID").fault, Fault::invalid);
  // An application's prefix and name.
  EXPECT_EQ(grantable("Toms:dns").fault, Fault::invalid);
  EXPECT_EQ(grantable("9toms:dns").fault, Fault::invalid);
  EXPECT_EQ(grantable(":dns").fault, Fault::invalid);
  EXPECT_EQ(grantable("toms:").fault, Fault::invalid);
  EXPECT_EQ(grantable(std::string(33, 'a') + ":x").fault, Fault::invalid);
  // Lir's prefix holds only topic scopes.
  EXPECT_EQ(grantable("lir:admin").fault, Fault::invalid);
  EXPECT_EQ(grantable("lir:sub:a/#/b").fault, Fault::invalid);
  EXPECT_EQ(grantable("two words").fault, Fault::invalid);
}

TEST(Scope, PrefixIsBeforeTheFirstColon) {
  EXPECT_EQ(prefix_of("lir:sub:a:b"), "lir");
  EXPECT_EQ(prefix_of("toms:dns"), "toms");
  EXPECT_FALSE(prefix_of("openid"));
  EXPECT_TRUE(valid_prefix("a"));
  EXPECT_TRUE(valid_prefix("toms-hub2"));
  EXPECT_FALSE(valid_prefix(""));
  EXPECT_FALSE(valid_prefix("-toms"));
  EXPECT_FALSE(valid_prefix("to.ms"));
}

TEST(Scope, SplitAndJoin) {
  EXPECT_EQ(split("openid  profile email"), (std::vector<std::string>{"openid", "profile", "email"}));
  EXPECT_EQ(split(""), std::vector<std::string>{});
  EXPECT_EQ(split("   "), std::vector<std::string>{});
  EXPECT_FALSE(split("openid pro\"file"));
  EXPECT_EQ(join({"profile", "openid", "profile"}), "openid profile");
  EXPECT_EQ(united({"b", "a", "b", "c", "a"}), (std::vector<std::string>{"a", "b", "c"}));
}

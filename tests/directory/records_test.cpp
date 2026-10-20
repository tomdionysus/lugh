#include "directory/records.h"

#include <gtest/gtest.h>

using namespace lugh::directory;

TEST(Records, NamesAreFoldedAndChecked) {
  EXPECT_EQ(normal_name("Alice"), "alice");
  EXPECT_EQ(normal_name("a.b_c-d9"), "a.b_c-d9");
  EXPECT_EQ(normal_name("9lives"), "9lives");
  EXPECT_FALSE(normal_name(""));
  EXPECT_FALSE(normal_name(".alice"));
  EXPECT_FALSE(normal_name("-alice"));
  EXPECT_FALSE(normal_name("al ice"));
  EXPECT_FALSE(normal_name("alice@example.com"));
  EXPECT_FALSE(normal_name("\xc3\xa1lice"));
  EXPECT_TRUE(normal_name(std::string(64, 'a')));
  EXPECT_FALSE(normal_name(std::string(65, 'a')));
}

TEST(Records, AddressesAreFoldedAndChecked) {
  EXPECT_EQ(normal_email("Alice@Example.COM"), "alice@example.com");
  EXPECT_FALSE(normal_email("alice"));
  EXPECT_FALSE(normal_email("@example.com"));
  EXPECT_FALSE(normal_email("alice@"));
  EXPECT_FALSE(normal_email("alice@example"));
  EXPECT_FALSE(normal_email("alice@.com"));
  EXPECT_FALSE(normal_email("alice@example."));
  EXPECT_FALSE(normal_email("a@b@example.com"));
  EXPECT_FALSE(normal_email("al ice@example.com"));
  EXPECT_FALSE(normal_email("alice@example.com\n"));
}

TEST(Records, PrintableIsUtf8WithoutControls) {
  EXPECT_TRUE(printable("Alice Smith", 128));
  EXPECT_TRUE(printable("\xc3\x81lvaro \xe6\x9d\x8e \xf0\x9f\x8c\x8a", 128));
  EXPECT_TRUE(printable("", 128));
  EXPECT_FALSE(printable("tab\there", 128));
  EXPECT_FALSE(printable("del\x7f", 128));
  EXPECT_FALSE(printable("\xc2\x85", 128));          // C1 control
  EXPECT_FALSE(printable("\xc0\xaf", 128));          // overlong
  EXPECT_FALSE(printable("\xed\xa0\x80", 128));      // surrogate
  EXPECT_FALSE(printable("\xf4\x90\x80\x80", 128));  // past U+10FFFF
  EXPECT_FALSE(printable("\xe6\x9d", 128));          // cut short
  EXPECT_FALSE(printable(std::string(129, 'a'), 128));
}

TEST(Records, UserRoundTrips) {
  User user;
  user.kind = Kind::service;
  user.enrolled = true;
  user.disabled = true;
  user.name = "backup";
  user.email = "";
  user.display_name = "Backup \xe2\x80\x94 nightly";
  user.created = 1;
  user.updated = 2;

  const auto decoded = decode_user(encode(user));
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->kind, Kind::service);
  EXPECT_TRUE(decoded->enrolled);
  EXPECT_TRUE(decoded->disabled);
  EXPECT_EQ(decoded->name, "backup");
  EXPECT_EQ(decoded->display_name, user.display_name);
  EXPECT_EQ(decoded->created, 1u);
  EXPECT_EQ(decoded->updated, 2u);
}

TEST(Records, DecodingRefusesWhatEncodingWouldNotMake) {
  User user;
  user.name = "alice";
  auto bytes = encode(user);

  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(decode_user(longer));
  EXPECT_FALSE(decode_user(std::span(bytes).first(bytes.size() - 1)));

  auto kind = bytes;
  kind[1] = 9;
  EXPECT_FALSE(decode_user(kind));

  auto flags = bytes;
  flags[2] = 0x80;
  EXPECT_FALSE(decode_user(flags));

  auto format = bytes;
  format[0] = 2;
  EXPECT_FALSE(decode_user(format));
}

TEST(Records, GroupAndMembershipRoundTrip) {
  Group group;
  group.name = "admins";
  group.description = "Run the place";
  group.created = 5;
  group.updated = 6;
  const auto decoded = decode_group(encode(group));
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->name, "admins");
  EXPECT_EQ(decoded->description, "Run the place");

  Membership membership;
  membership.group_id = "g";
  membership.user_id = "u";
  membership.added = 7;
  const auto back = decode_membership(encode(membership));
  ASSERT_TRUE(back);
  EXPECT_EQ(back->group_id, "g");
  EXPECT_EQ(back->user_id, "u");
  EXPECT_EQ(back->added, 7u);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/core/codec.h"
#include "lugh/directory/records.h"

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
  user.given_name = "Night";
  user.family_name = "Backup";
  user.posix_number = 10042;
  user.created = 1;
  user.updated = 2;

  const auto decoded = decode_user(encode(user));
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->kind, Kind::service);
  EXPECT_TRUE(decoded->enrolled);
  EXPECT_TRUE(decoded->disabled);
  EXPECT_EQ(decoded->name, "backup");
  EXPECT_EQ(decoded->display_name, user.display_name);
  EXPECT_EQ(decoded->given_name, "Night");
  EXPECT_EQ(decoded->family_name, "Backup");
  EXPECT_EQ(decoded->posix_number, 10042u);
  EXPECT_EQ(decoded->created, 1u);
  EXPECT_EQ(decoded->updated, 2u);

  User unnumbered;
  unnumbered.name = "alice";
  const auto plain = decode_user(encode(unnumbered));
  ASSERT_TRUE(plain);
  EXPECT_FALSE(plain->posix_number);
  EXPECT_TRUE(plain->given_name.empty());
}

// The frozen store holds users and groups written before the name parts and the POSIX
// number existed; they are read as having neither.
TEST(Records, FormatOneIsStillRead) {
  lugh::SecureWriter writer;
  writer.u8(1);
  writer.u8(1);     // person
  writer.u8(0x01);  // enrolled
  writer.string("alice");
  writer.string("alice@example.com");
  writer.string("Alice Smith");
  writer.u64(3);
  writer.u64(4);
  const auto user = decode_user(writer.take());
  ASSERT_TRUE(user);
  EXPECT_EQ(user->name, "alice");
  EXPECT_EQ(user->display_name, "Alice Smith");
  EXPECT_TRUE(user->given_name.empty());
  EXPECT_TRUE(user->family_name.empty());
  EXPECT_FALSE(user->posix_number);
  EXPECT_EQ(user->updated, 4u);

  lugh::SecureWriter old_group;
  old_group.u8(1);
  old_group.string("admins");
  old_group.string("Run the place");
  old_group.u64(5);
  old_group.u64(6);
  const auto group = decode_group(old_group.take());
  ASSERT_TRUE(group);
  EXPECT_EQ(group->name, "admins");
  EXPECT_FALSE(group->posix_number);
  EXPECT_EQ(group->updated, 6u);
}

// A POSIX number is present or absent, never "absent with a value".
TEST(Records, PosixNumberFlagIsChecked) {
  User user;
  user.name = "alice";
  auto bytes = encode(user);
  // Format, kind, flags, then three strings (u32 length each, "alice" and two empty), then
  // the flag byte and the u32 number.
  const std::size_t flag = 3 + (4 + 5) + 4 + 4;
  ASSERT_EQ(bytes[flag], 0);
  auto wrong = bytes;
  wrong[flag + 4] = 7;
  EXPECT_FALSE(decode_user(wrong));
  auto two = bytes;
  two[flag] = 2;
  EXPECT_FALSE(decode_user(two));
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
  format[0] = 3;
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

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "core/byte_io.h"

#include <gtest/gtest.h>

#include "core/secure_bytes.h"

using lugh::ByteReader;
using lugh::Bytes;
using lugh::ByteWriter;

TEST(ByteIo, WritesBigEndian) {
  Bytes out;
  ByteWriter writer(out);
  writer.u8(0xab);
  writer.u32(0x01020304);
  writer.text("hi");
  writer.bytes(Bytes{9, 8});
  EXPECT_EQ(out, (Bytes{0xab, 1, 2, 3, 4, 'h', 'i', 9, 8}));
}

TEST(ByteIo, ReadsWhatWasWritten) {
  Bytes out;
  ByteWriter writer(out);
  writer.u8(7);
  writer.u32(0xdeadbeef);
  writer.text("abc");

  ByteReader reader(out);
  EXPECT_EQ(reader.u8(), 7);
  EXPECT_EQ(reader.u32(), 0xdeadbeefu);
  const auto rest = reader.bytes(3);
  ASSERT_TRUE(rest);
  EXPECT_EQ(std::string(rest->begin(), rest->end()), "abc");
  EXPECT_TRUE(reader.done());
}

TEST(ByteIo, NeverReadsPastTheEnd) {
  const Bytes three{1, 2, 3};
  ByteReader reader(three);
  EXPECT_FALSE(reader.u32());
  EXPECT_FALSE(reader.bytes(4));
  EXPECT_EQ(reader.offset(), 0u);
  EXPECT_EQ(reader.rest().size(), 3u);
  EXPECT_FALSE(reader.u8());
}

TEST(ByteIo, WideFields) {
  Bytes out;
  ByteWriter writer(out);
  writer.u16(0xbeef);
  writer.u64(0x0102030405060708ull);
  EXPECT_EQ(out, (Bytes{0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8}));

  ByteReader reader(out);
  EXPECT_EQ(reader.u16(), 0xbeef);
  EXPECT_EQ(reader.u64(), 0x0102030405060708ull);
  EXPECT_FALSE(reader.u16());

  const Bytes seven(7, 0);
  ByteReader short_reader(seven);
  EXPECT_FALSE(short_reader.u64());
}

TEST(ByteIo, WritesIntoSecureBytes) {
  lugh::SecureBytes out;
  ByteWriter writer(out);
  writer.u32(1);
  EXPECT_EQ(out.size(), 4u);
}

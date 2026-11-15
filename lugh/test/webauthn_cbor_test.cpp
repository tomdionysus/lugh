//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <limits>

#include "lugh/webauthn/cbor.h"

using lugh::webauthn::cbor::decode;
using lugh::webauthn::cbor::Value;
using Kind = Value::Kind;

namespace {

std::vector<std::uint8_t> hex(std::string_view text) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(text.substr(i, 2)), nullptr, 16)));
  return out;
}

std::optional<Value> decoded(std::string_view text) { return decode(hex(text)); }

std::optional<std::int64_t> integer(std::string_view text) {
  const auto value = decoded(text);
  if (!value || value->kind != Kind::integer) return std::nullopt;
  return value->integer;
}

}  // namespace

// RFC 8949 Appendix A, the integers.
TEST(Cbor, Rfc8949Integers) {
  EXPECT_EQ(integer("00"), 0);
  EXPECT_EQ(integer("01"), 1);
  EXPECT_EQ(integer("0a"), 10);
  EXPECT_EQ(integer("17"), 23);
  EXPECT_EQ(integer("1818"), 24);
  EXPECT_EQ(integer("1819"), 25);
  EXPECT_EQ(integer("1864"), 100);
  EXPECT_EQ(integer("1903e8"), 1000);
  EXPECT_EQ(integer("1a000f4240"), 1000000);
  EXPECT_EQ(integer("1b000000e8d4a51000"), 1000000000000);
  EXPECT_EQ(integer("20"), -1);
  EXPECT_EQ(integer("29"), -10);
  EXPECT_EQ(integer("3863"), -100);
  EXPECT_EQ(integer("3903e7"), -1000);
  // COSE's RS256, -257.
  EXPECT_EQ(integer("390100"), -257);
}

// Past what an int64_t holds: RFC 8949's 2^64 - 1 and -2^64.
TEST(Cbor, IntegersPastInt64AreRefused) {
  EXPECT_FALSE(decoded("1bffffffffffffffff"));
  EXPECT_FALSE(decoded("3bffffffffffffffff"));
  EXPECT_EQ(integer("1b7fffffffffffffff"), std::numeric_limits<std::int64_t>::max());
  EXPECT_EQ(integer("3b7fffffffffffffff"), std::numeric_limits<std::int64_t>::min());
}

TEST(Cbor, Rfc8949SimpleValuesAndStrings) {
  EXPECT_EQ(decoded("f4")->kind, Kind::boolean);
  EXPECT_FALSE(decoded("f4")->boolean);
  EXPECT_TRUE(decoded("f5")->boolean);
  EXPECT_EQ(decoded("f6")->kind, Kind::null);

  EXPECT_EQ(decoded("40")->kind, Kind::bytes);
  EXPECT_EQ(decoded("40")->string, "");
  EXPECT_EQ(decoded("4401020304")->string, std::string("\x01\x02\x03\x04", 4));
  EXPECT_EQ(decoded("60")->kind, Kind::text);
  EXPECT_EQ(decoded("6161")->string, "a");
  EXPECT_EQ(decoded("6449455446")->string, "IETF");
  EXPECT_EQ(decoded("62c3bc")->string, "\xc3\xbc");
}

TEST(Cbor, Rfc8949ArraysAndMaps) {
  const auto empty = decoded("80");
  ASSERT_TRUE(empty);
  EXPECT_EQ(empty->kind, Kind::array);
  EXPECT_TRUE(empty->items.empty());

  const auto nested = decoded("8301820203820405");
  ASSERT_TRUE(nested);
  ASSERT_EQ(nested->items.size(), 3u);
  EXPECT_EQ(nested->items[0].integer, 1);
  EXPECT_EQ(nested->items[2].items[1].integer, 5);

  const auto numbers = decoded("a201020304");
  ASSERT_TRUE(numbers);
  ASSERT_NE(numbers->find(3), nullptr);
  EXPECT_EQ(numbers->find(3)->integer, 4);
  EXPECT_EQ(numbers->find(2), nullptr);

  const auto named = decoded("a26161016162820203");
  ASSERT_TRUE(named);
  ASSERT_NE(named->find("b"), nullptr);
  EXPECT_EQ(named->find("b")->items.size(), 2u);
  EXPECT_EQ(named->find(1), nullptr) << "a text key is not an integer key";
}

// What RFC 8949 allows and WebAuthn never sends, refused.
TEST(Cbor, TagsFloatsUndefinedAndIndefiniteLengthsAreRefused) {
  EXPECT_FALSE(decoded("c074323031332d30332d32315432303a30343a30305a")) << "tag 0";
  EXPECT_FALSE(decoded("f90000")) << "a half float";
  EXPECT_FALSE(decoded("fb3ff199999999999a")) << "a double";
  EXPECT_FALSE(decoded("f7")) << "undefined";
  EXPECT_FALSE(decoded("f0")) << "simple value 16";
  EXPECT_FALSE(decoded("5f42010243030405ff")) << "an indefinite byte string";
  EXPECT_FALSE(decoded("9fff")) << "an indefinite array";
  EXPECT_FALSE(decoded("bf6161f5ff")) << "an indefinite map";
  EXPECT_FALSE(decoded("1c")) << "a reserved additional value";
}

// CTAP2's canonical form: each length and integer in its shortest encoding.
TEST(Cbor, OnlyTheShortestEncodingIsTaken) {
  EXPECT_FALSE(decoded("1817")) << "23 in one byte";
  EXPECT_FALSE(decoded("190017")) << "23 in two bytes";
  EXPECT_FALSE(decoded("1900ff")) << "255 in two bytes";
  EXPECT_FALSE(decoded("1a0000ffff")) << "65535 in four bytes";
  EXPECT_FALSE(decoded("1b00000000ffffffff")) << "2^32 - 1 in eight bytes";
  EXPECT_FALSE(decoded("580161")) << "a one-byte string's length in a byte";
  EXPECT_TRUE(decoded("1818"));
}

TEST(Cbor, AKeyRepeatedIsRefused) {
  EXPECT_FALSE(decoded("a201020103"));
  EXPECT_FALSE(decoded("a2616101616102"));
  // An integer 1 and a text "1" are different keys.
  EXPECT_TRUE(decoded("a20102613103"));
}

TEST(Cbor, TextMustBeUtf8) {
  EXPECT_FALSE(decoded("62c080")) << "an overlong NUL";
  EXPECT_FALSE(decoded("63eda080")) << "a surrogate";
  EXPECT_FALSE(decoded("61ff"));
  EXPECT_TRUE(decoded("42c080")) << "bytes are bytes";
}

TEST(Cbor, LengthsAreCheckedAgainstWhatIsLeft) {
  EXPECT_FALSE(decoded("")) << "nothing";
  EXPECT_FALSE(decoded("44010203")) << "a string one byte short";
  EXPECT_FALSE(decoded("5bffffffffffffffff")) << "a string as long as memory";
  EXPECT_FALSE(decoded("9affffffff")) << "a count of items that are not there";
  EXPECT_FALSE(decoded("baffffffff")) << "a count of entries that are not there";
  EXPECT_FALSE(decoded("8301")) << "an array cut short";
  EXPECT_FALSE(decoded("1903")) << "an integer cut short";
}

TEST(Cbor, NestingIsBounded) {
  std::string deep;
  for (std::size_t i = 0; i < lugh::webauthn::cbor::kMostDepth; ++i) deep += "81";
  EXPECT_TRUE(decoded(deep + "00")) << "16 levels inside the outermost";
  EXPECT_FALSE(decoded(deep + "8100")) << "one deeper";
}

TEST(Cbor, ItemsAreBounded) {
  // An array of kMostItems zeros is one item too many, counting the array itself.
  std::string many = "991000";
  for (std::size_t i = 0; i < lugh::webauthn::cbor::kMostItems; ++i) many += "00";
  EXPECT_FALSE(decoded(many));
  std::string enough = "990fff";
  for (std::size_t i = 0; i + 1 < lugh::webauthn::cbor::kMostItems; ++i) enough += "00";
  EXPECT_TRUE(decoded(enough));
}

// Attested credential data is followed by its COSE key and then extensions: with `used`, an
// item is read from the front and its end reported.
TEST(Cbor, AnItemFromTheFront) {
  const auto bytes = hex("a10102ff00");
  std::size_t used = 0;
  const auto value = decode(bytes, &used);
  ASSERT_TRUE(value);
  EXPECT_EQ(used, 3u);
  EXPECT_FALSE(decode(bytes)) << "without `used`, the item must be everything";
}

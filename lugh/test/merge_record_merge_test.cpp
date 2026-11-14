//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>

#include "lugh/merge/record_merge.h"

using namespace lugh::merge;
using lugh::SecureBuffer;

namespace {

SecureBuffer bytes_of(const std::string& text) { return SecureBuffer(text.begin(), text.end()); }

Envelope live(std::uint64_t version, const std::string& writer, const std::string& value) { return Envelope{version, writer, false, bytes_of(value)}; }
Envelope gone(std::uint64_t version, const std::string& writer) { return Envelope{version, writer, true, {}}; }

std::string text_of(const Envelope& envelope) { return std::string(envelope.value.begin(), envelope.value.end()); }

}  // namespace

TEST(RecordEnvelope, RoundTrips) {
  for (const auto& envelope : {live(7, "node-a", "alice's record"), gone(9, "node-b"), live(0, "", "")}) {
    const auto back = decode(encode(envelope));
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, envelope);
  }
}

TEST(RecordEnvelope, WhatIsNotOne) {
  auto bytes = encode(live(1, "a", "x"));
  auto wrong_format = bytes;
  wrong_format[0] = 2;
  EXPECT_FALSE(decode(wrong_format));
  auto longer = bytes;
  longer.push_back(0);
  EXPECT_FALSE(decode(longer)) << "bytes left over";
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    EXPECT_FALSE(decode(std::span<const unsigned char>(bytes.data(), length))) << length;
  }

  // A tombstone with a value is not one Lugh wrote: a removal keeps nothing.
  auto with_value = encode(live(1, "a", "secret"));
  const auto state_at = 1 + 8 + 4 + 1;
  with_value[state_at] = 1;
  EXPECT_FALSE(decode(with_value));
  auto bad_state = encode(live(1, "a", "x"));
  bad_state[state_at] = 2;
  EXPECT_FALSE(decode(bad_state));
}

// the maintainer, 2026-11-13: an edit on both sides keeps the higher version, then the higher node id.
TEST(RecordMerge, TheHigherVersionThenTheHigherWriter) {
  EXPECT_EQ(text_of(winner(live(3, "node-a", "three"), live(2, "node-z", "two"))), "three");
  EXPECT_EQ(text_of(winner(live(2, "node-z", "two"), live(3, "node-a", "three"))), "three");
  EXPECT_EQ(text_of(winner(live(3, "node-a", "from a"), live(3, "node-b", "from b"))), "from b");
  EXPECT_EQ(text_of(winner(live(3, "node-b", "from b"), live(3, "node-a", "from a"))), "from b");
}

// A removal beats an edit, however new the edit.
TEST(RecordMerge, ARemovalBeatsAnyEdit) {
  EXPECT_TRUE(winner(gone(2, "node-a"), live(50, "node-z", "edited later")).removed);
  EXPECT_TRUE(winner(live(50, "node-z", "edited later"), gone(2, "node-a")).removed);

  Records left{{"users/1", live(4, "node-a", "renamed")}};
  Records right{{"users/1", gone(4, "node-b")}};
  const auto merged = merge(Records{{"users/1", live(3, "node-a", "alice")}}, {left, right});
  ASSERT_TRUE(merged.at("users/1").removed);
  EXPECT_TRUE(merged.at("users/1").value.empty()) << "nothing of the removed record is kept";
}

// A removed key is never used again, so a later edit cannot bring it back.
TEST(RecordMerge, ARemovedRecordNeverComesBack) {
  Records removed{{"users/1", gone(5, "node-a")}};
  EXPECT_FALSE(writable(removed, "users/1"));
  EXPECT_TRUE(writable(removed, "users/2"));
  // Even an edit carrying a far higher version, from a node that missed the removal.
  const auto merged = merge(std::nullopt, {removed, Records{{"users/1", live(999, "node-z", "resurrected")}}});
  EXPECT_TRUE(merged.at("users/1").removed);
}

TEST(RecordMerge, KeysFromEveryHead) {
  Records a{{"users/1", live(1, "node-a", "alice")}};
  Records b{{"users/2", live(1, "node-b", "bob")}};
  const auto merged = merge(std::nullopt, {a, b});
  EXPECT_EQ(merged.size(), 2u);
  EXPECT_EQ(text_of(merged.at("users/1")), "alice");
  EXPECT_EQ(text_of(merged.at("users/2")), "bob");
  EXPECT_TRUE(merge(std::nullopt, {}).empty());
}

// Every node must reach the same map whatever order the heads arrive in, and joining the same heads again changes nothing.
TEST(RecordMerge, TheSameMapInAnyOrder) {
  std::uint32_t state = 7;
  const auto random = [&](std::uint32_t below) {
    state = state * 1664525u + 1013904223u;
    return (state >> 8) % below;
  };
  for (int round = 0; round < 500; ++round) {
    std::vector<Records> heads(3);
    for (auto& head : heads) {
      for (int i = 0; i < 6; ++i) {
        const auto key = "k/" + std::to_string(random(5));
        const auto writer = std::string("node-") + static_cast<char>('a' + random(3));
        head[key] = random(4) == 0 ? gone(random(6), writer) : live(random(6), writer, "v" + std::to_string(random(3)));
      }
    }
    const auto expected = merge(std::nullopt, heads);
    std::vector<int> order{0, 1, 2};
    do {
      EXPECT_EQ(merge(std::nullopt, {heads[order[0]], heads[order[1]], heads[order[2]]}), expected) << round;
      // Associative: two at a time, in any grouping.
      EXPECT_EQ(merge(std::nullopt, {merge(std::nullopt, {heads[order[0]], heads[order[1]]}), heads[order[2]]}), expected) << round;
    } while (std::next_permutation(order.begin(), order.end()));
    EXPECT_EQ(merge(std::nullopt, {expected, expected}), expected) << "idempotent";
    EXPECT_EQ(merge(std::nullopt, {expected, heads[1]}), expected) << "a head already joined changes nothing";
  }
}

// Stack requirement e, the maintainer 2026-11-13: two alices from a split are both kept, and a lookup by the name is refused.
TEST(UniqueIndexTest, TwoRecordsWithOneNameAreAmbiguous) {
  UniqueIndex names;
  names.add("alice", "users/1");
  EXPECT_EQ(names.find("alice").key, "users/1");
  EXPECT_FALSE(names.find("alice").ambiguous);

  names.add("alice", "users/2");
  const auto found = names.find("alice");
  EXPECT_FALSE(found.key);
  EXPECT_TRUE(found.ambiguous);
  EXPECT_EQ(names.ambiguous(), (std::vector<std::string>{"alice"}));

  // Renamed by an administrator: unique again, and each name finds its own.
  names.remove("alice", "users/2");
  names.add("alice2", "users/2");
  EXPECT_EQ(names.find("alice").key, "users/1");
  EXPECT_EQ(names.find("alice2").key, "users/2");
  EXPECT_TRUE(names.ambiguous().empty());

  EXPECT_FALSE(names.find("nobody").key);
  EXPECT_FALSE(names.find("nobody").ambiguous);
  names.remove("nobody", "users/9");
  names.add("alice", "users/1");
  EXPECT_EQ(names.find("alice").key, "users/1") << "adding the same pair twice is one";
}

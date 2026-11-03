//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "store/log_format.h"

#include <gtest/gtest.h>

#include "fakes/fixed_random.h"
#include "helpers/hex.h"

using namespace lugh::store;

namespace {

const lugh::SecureBytes kKey(32, 0x42);

KeyFor only_epoch_one() {
  return [](std::uint32_t epoch) -> const lugh::SecureBytes* { return epoch == 1 ? &kKey : nullptr; };
}

Change put(std::string key, std::uint64_t version, std::string value) {
  Change change;
  change.key = std::move(key);
  change.version = version;
  change.value.assign(value.begin(), value.end());
  return change;
}

// A log of the changes given, under epoch 1.
lugh::Bytes log_of(const std::vector<Change>& changes, FixedRandom& random, std::string table = "users") {
  const auto header = make_file_header(table, 1, kKey, random).value;
  auto file = encode_file_header(header);
  auto previous = header.tag();
  for (const auto& change : changes) {
    const auto framed = seal_change(change, table, 1, kKey, previous, random).value;
    file.insert(file.end(), framed.bytes.begin(), framed.bytes.end());
    previous = framed.frame.tag();
  }
  return file;
}

std::size_t header_length(const lugh::Bytes& file) { return decode_file_header(file)->length; }

}  // namespace

TEST(LogFormat, AHeader) {
  FixedRandom random;
  const auto header = make_file_header("users", 3, kKey, random);
  ASSERT_TRUE(header.ok) << header.error;
  const auto bytes = encode_file_header(header.value);
  EXPECT_EQ(bytes.size(), 8u + 1 + 5 + 16 + 4 + 28);

  const auto parsed = decode_file_header(bytes);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->length, bytes.size());
  EXPECT_EQ(parsed->header.table, "users");
  EXPECT_EQ(parsed->header.epoch, 3u);
  EXPECT_TRUE(verify_file_header(parsed->header, kKey));
  EXPECT_FALSE(verify_file_header(parsed->header, lugh::SecureBytes(32, 0x43)));
}

TEST(LogFormat, AnEditedHeaderDoesNotVerify) {
  FixedRandom random;
  const auto bytes = encode_file_header(make_file_header("users", 1, kKey, random).value);
  for (std::size_t i = 8; i < bytes.size(); ++i) {
    auto edited = bytes;
    edited[i] ^= 1;
    const auto parsed = decode_file_header(edited);
    EXPECT_TRUE(!parsed || !verify_file_header(parsed->header, kKey)) << i;
  }
}

TEST(LogFormat, ScanReadsEveryFrame) {
  FixedRandom random;
  Change removal;
  removal.operation = Operation::remove;
  removal.key = "u1";
  removal.version = 2;
  const auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob"), removal}, random);

  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok) << scan.error;
  EXPECT_EQ(scan.value.end, Scan::End::clean);
  EXPECT_EQ(scan.value.valid_length, file.size());
  ASSERT_EQ(scan.value.entries.size(), 3u);
  EXPECT_EQ(scan.value.entries[1].change.key, "u2");
  EXPECT_EQ(std::string(scan.value.entries[1].change.value.begin(), scan.value.entries[1].change.value.end()), "bob");
  EXPECT_EQ(scan.value.entries[2].change.operation, Operation::remove);
}

TEST(LogFormat, NoPlaintextOnDisk) {
  FixedRandom random;
  const auto file = log_of({put("u1", 1, "a secret value")}, random);
  const std::string secret = "a secret value";
  EXPECT_EQ(std::search(file.begin(), file.end(), secret.begin(), secret.end()), file.end());
  const std::string key = "u1";
  EXPECT_EQ(std::search(file.begin(), file.end(), key.begin(), key.end()), file.end());
}

TEST(LogFormat, TheHeaderMustBeThisTables) {
  FixedRandom random;
  const auto file = log_of({}, random, "groups");
  const auto scan = scan_log(file, "users", only_epoch_one());
  EXPECT_FALSE(scan.ok);
  EXPECT_NE(scan.error.find("groups"), std::string::npos);
}

TEST(LogFormat, TheWrongKeyIsRefusedAtTheHeader) {
  FixedRandom random;
  const auto file = log_of({put("u1", 1, "alice")}, random);
  const lugh::SecureBytes other(32, 0x99);
  const auto scan = scan_log(file, "users", [&](std::uint32_t) { return &other; });
  EXPECT_FALSE(scan.ok);
  EXPECT_NE(scan.error.find("does not open"), std::string::npos);

  EXPECT_FALSE(scan_log(file, "users", [](std::uint32_t) -> const lugh::SecureBytes* { return nullptr; }).ok);
}

TEST(LogFormat, EveryTruncationIsATornTail) {
  FixedRandom random;
  const auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob")}, random);
  const auto first_end = header_length(file) + scan_log(file, "users", only_epoch_one()).value.entries[0].frame.size();

  for (std::size_t length = header_length(file) + 1; length < file.size(); ++length) {
    const auto scan = scan_log(std::span(file).first(length), "users", only_epoch_one());
    ASSERT_TRUE(scan.ok) << length;
    // Cut exactly between frames, the log is whole, just shorter.
    EXPECT_EQ(scan.value.end, length == first_end ? Scan::End::clean : Scan::End::torn) << length;
    EXPECT_EQ(scan.value.entries.size(), length < first_end ? 0u : 1u) << length;
  }
}

TEST(LogFormat, ZerosAfterTheLastFrameAreATornTail) {
  FixedRandom random;
  auto file = log_of({put("u1", 1, "alice")}, random);
  const auto clean = file.size();
  file.resize(file.size() + 4096, 0);
  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::torn);
  EXPECT_EQ(scan.value.valid_length, clean);
  EXPECT_EQ(scan.value.entries.size(), 1u);
}

TEST(LogFormat, DamageBeforeAGoodFrameIsDamage) {
  FixedRandom random;
  auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob")}, random);
  file[header_length(file) + 30] ^= 1;  // inside the first frame's ciphertext
  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::damaged);
  EXPECT_EQ(scan.value.problem_offset, header_length(file));
  EXPECT_TRUE(scan.value.entries.empty());
}

TEST(LogFormat, FramesCannotBeReordered) {
  FixedRandom random;
  const auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob")}, random);
  const auto start = header_length(file);
  const auto half = (file.size() - start) / 2;

  lugh::Bytes swapped(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(start));
  swapped.insert(swapped.end(), file.begin() + static_cast<std::ptrdiff_t>(start + half), file.end());
  swapped.insert(swapped.end(), file.begin() + static_cast<std::ptrdiff_t>(start), file.begin() + static_cast<std::ptrdiff_t>(start + half));

  const auto scan = scan_log(swapped, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::damaged);
  EXPECT_TRUE(scan.value.entries.empty());
}

TEST(LogFormat, AFrameCannotBeReplayed) {
  FixedRandom random;
  const auto file = log_of({put("u1", 1, "alice"), put("u1", 2, "alicia")}, random);
  const auto start = header_length(file);
  const auto half = (file.size() - start) / 2;

  auto replayed = file;
  replayed.insert(replayed.end(), file.begin() + static_cast<std::ptrdiff_t>(start), file.begin() + static_cast<std::ptrdiff_t>(start + half));
  const auto scan = scan_log(replayed, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.entries.size(), 2u);
  EXPECT_NE(scan.value.end, Scan::End::clean);
  EXPECT_EQ(scan.value.valid_length, file.size());
}

TEST(LogFormat, AFrameCannotMoveToAnotherTable) {
  FixedRandom random;
  const auto users = log_of({put("u1", 1, "alice")}, random, "users");
  const auto groups = log_of({}, random, "groups");

  auto moved = groups;
  moved.insert(moved.end(), users.begin() + static_cast<std::ptrdiff_t>(header_length(users)), users.end());
  const auto scan = scan_log(moved, "groups", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_TRUE(scan.value.entries.empty());
}

TEST(LogFormat, AnEpochWithNoKeyIsDamageNotATear) {
  FixedRandom random;
  const auto header = make_file_header("users", 1, kKey, random).value;
  auto file = encode_file_header(header);
  const auto framed = seal_change(put("u1", 1, "alice"), "users", 2, kKey, header.tag(), random).value;
  file.insert(file.end(), framed.bytes.begin(), framed.bytes.end());

  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::damaged);
  EXPECT_NE(scan.value.problem.find("epoch 2"), std::string::npos);
}

TEST(LogFormat, SealRefusesWhatCannotBeRead) {
  FixedRandom random;
  const lugh::Bytes previous(kTagBytes, 0);
  EXPECT_FALSE(seal_change(put("", 1, "x"), "users", 1, kKey, previous, random).ok);
  EXPECT_FALSE(seal_change(put("k", 0, "x"), "users", 1, kKey, previous, random).ok);
  EXPECT_FALSE(seal_change(put("k", 1, "x"), "users", 0, kKey, previous, random).ok);
  EXPECT_FALSE(seal_change(put("k", 1, "x"), "users", 1, kKey, lugh::Bytes(3, 0), random).ok);
  Change removal = put("k", 1, "not empty");
  removal.operation = Operation::remove;
  EXPECT_FALSE(seal_change(removal, "users", 1, kKey, previous, random).ok);
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>

#include "lugh/store/log_format.h"
#include "lugh/test/fixtures/hex.h"

using namespace lugh::store;

namespace {

const lugh::SecureBuffer kKey(32, 0x42);

KeyFor only_epoch_one() {
  return [](std::uint32_t epoch) -> const lugh::SecureBuffer* { return epoch == 1 ? &kKey : nullptr; };
}

Change put(std::string key, std::uint64_t version, std::string value) {
  Change change;
  change.key = std::move(key);
  change.version = version;
  change.value.assign(value.begin(), value.end());
  return change;
}

// A log of the changes given, under epoch 1.
lugh::Bytes log_of(const std::vector<Change>& changes, std::string table = "users") {
  const auto header = make_file_header(table, 1, kKey).value;
  auto file = encode_file_header(header);
  auto previous = header.tag();
  for (const auto& change : changes) {
    const auto framed = seal_change(change, table, 1, kKey, previous).value;
    file.insert(file.end(), framed.bytes.begin(), framed.bytes.end());
    previous = framed.frame.tag();
  }
  return file;
}

std::size_t header_length(const lugh::Bytes& file) { return decode_file_header(file)->length; }

}  // namespace

TEST(LogFormat, AHeader) {
  const auto header = make_file_header("users", 3, kKey);
  ASSERT_TRUE(header.ok) << header.error;
  const auto bytes = encode_file_header(header.value);
  EXPECT_EQ(bytes.size(), 8u + 1 + 5 + 16 + 4 + 28);

  const auto parsed = decode_file_header(bytes);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->length, bytes.size());
  EXPECT_EQ(parsed->header.table, "users");
  EXPECT_EQ(parsed->header.epoch, 3u);
  EXPECT_TRUE(verify_file_header(parsed->header, kKey));
  EXPECT_FALSE(verify_file_header(parsed->header, lugh::SecureBuffer(32, 0x43)));
}

TEST(LogFormat, AnEditedHeaderDoesNotVerify) {
  const auto bytes = encode_file_header(make_file_header("users", 1, kKey).value);
  for (std::size_t i = 8; i < bytes.size(); ++i) {
    auto edited = bytes;
    edited[i] ^= 1;
    const auto parsed = decode_file_header(edited);
    EXPECT_TRUE(!parsed || !verify_file_header(parsed->header, kKey)) << i;
  }
}

TEST(LogFormat, ScanReadsEveryFrame) {
  Change removal;
  removal.operation = Operation::remove;
  removal.key = "u1";
  removal.version = 2;
  const auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob"), removal});

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
  const auto file = log_of({put("u1", 1, "a secret value")});
  const std::string secret = "a secret value";
  EXPECT_EQ(std::search(file.begin(), file.end(), secret.begin(), secret.end()), file.end());
  const std::string key = "u1";
  EXPECT_EQ(std::search(file.begin(), file.end(), key.begin(), key.end()), file.end());
}

TEST(LogFormat, TheHeaderMustBeThisTables) {
  const auto file = log_of({}, "groups");
  const auto scan = scan_log(file, "users", only_epoch_one());
  EXPECT_FALSE(scan.ok);
  EXPECT_NE(scan.error.find("groups"), std::string::npos);
}

TEST(LogFormat, TheWrongKeyIsRefusedAtTheHeader) {
  const auto file = log_of({put("u1", 1, "alice")});
  const lugh::SecureBuffer other(32, 0x99);
  const auto scan = scan_log(file, "users", [&](std::uint32_t) { return &other; });
  EXPECT_FALSE(scan.ok);
  EXPECT_NE(scan.error.find("does not open"), std::string::npos);

  EXPECT_FALSE(scan_log(file, "users", [](std::uint32_t) -> const lugh::SecureBuffer* { return nullptr; }).ok);
}

TEST(LogFormat, EveryTruncationIsATornTail) {
  const auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob")});
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
  auto file = log_of({put("u1", 1, "alice")});
  const auto clean = file.size();
  file.resize(file.size() + 4096, 0);
  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::torn);
  EXPECT_EQ(scan.value.valid_length, clean);
  EXPECT_EQ(scan.value.entries.size(), 1u);
}

TEST(LogFormat, DamageBeforeAGoodFrameIsDamage) {
  auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob")});
  file[header_length(file) + 30] ^= 1;  // inside the first frame's ciphertext
  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::damaged);
  EXPECT_EQ(scan.value.problem_offset, header_length(file));
  EXPECT_TRUE(scan.value.entries.empty());
}

TEST(LogFormat, FramesCannotBeReordered) {
  const auto file = log_of({put("u1", 1, "alice"), put("u2", 1, "bob")});
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
  const auto file = log_of({put("u1", 1, "alice"), put("u1", 2, "alicia")});
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
  const auto users = log_of({put("u1", 1, "alice")}, "users");
  const auto groups = log_of({}, "groups");

  auto moved = groups;
  moved.insert(moved.end(), users.begin() + static_cast<std::ptrdiff_t>(header_length(users)), users.end());
  const auto scan = scan_log(moved, "groups", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_TRUE(scan.value.entries.empty());
}

TEST(LogFormat, AnEpochWithNoKeyIsDamageNotATear) {
  const auto header = make_file_header("users", 1, kKey).value;
  auto file = encode_file_header(header);
  const auto framed = seal_change(put("u1", 1, "alice"), "users", 2, kKey, header.tag()).value;
  file.insert(file.end(), framed.bytes.begin(), framed.bytes.end());

  const auto scan = scan_log(file, "users", only_epoch_one());
  ASSERT_TRUE(scan.ok);
  EXPECT_EQ(scan.value.end, Scan::End::damaged);
  EXPECT_NE(scan.value.problem.find("epoch 2"), std::string::npos);
}

TEST(LogFormat, SealRefusesWhatCannotBeRead) {
  const lugh::Bytes previous(kTagBytes, 0);
  EXPECT_FALSE(seal_change(put("", 1, "x"), "users", 1, kKey, previous).ok);
  EXPECT_FALSE(seal_change(put("k", 0, "x"), "users", 1, kKey, previous).ok);
  EXPECT_FALSE(seal_change(put("k", 1, "x"), "users", 0, kKey, previous).ok);
  EXPECT_FALSE(seal_change(put("k", 1, "x"), "users", 1, kKey, lugh::Bytes(3, 0)).ok);
  Change removal = put("k", 1, "not empty");
  removal.operation = Operation::remove;
  EXPECT_FALSE(seal_change(removal, "users", 1, kKey, previous).ok);
}

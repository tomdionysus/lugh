//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/system/system_files.h"

#include <gtest/gtest.h>
#include <sys/stat.h>

#include <filesystem>

#include "lugh/test/fixtures/pools.h"
#include "lugh/test/fixtures/run.h"
#include "lugh/test/fixtures/temp_directory.h"

using lugh::Bytes;
using lugh::system::SystemFiles;

namespace {

Bytes bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }

unsigned mode_of(const std::filesystem::path& path) {
  struct stat status{};
  ::stat(path.c_str(), &status);
  return status.st_mode & 0777;
}

}  // namespace

TEST(SystemFiles, WritesAndReads) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = (dir.path() / "keyring").string();

  EXPECT_FALSE(run(files.exists(path)));
  ASSERT_TRUE(run(files.write(path, bytes("one"), false)).ok);
  EXPECT_TRUE(run(files.exists(path)));
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("one"));
  EXPECT_EQ(mode_of(path), 0600u);
  EXPECT_FALSE(std::filesystem::exists(path + ".new"));

  const auto secret = run(files.read_secret(path, 100));
  ASSERT_TRUE(secret.ok);
  EXPECT_EQ(std::string(secret.value.begin(), secret.value.end()), "one");
}

TEST(SystemFiles, ANewFileNeverReplacesOne) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = (dir.path() / "keyring").string();

  ASSERT_TRUE(run(files.write(path, bytes("first"), false)).ok);
  const auto again = run(files.write(path, bytes("second"), false));
  EXPECT_FALSE(again.ok);
  EXPECT_NE(again.error.find("not replaced"), std::string::npos);
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("first"));
}

TEST(SystemFiles, ReplaceReplaces) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = (dir.path() / "keyring").string();

  ASSERT_TRUE(run(files.write(path, bytes("first"), false)).ok);
  ASSERT_TRUE(run(files.write(path, bytes("second"), true)).ok);
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("second"));
  EXPECT_FALSE(std::filesystem::exists(path + ".new"));
}

TEST(SystemFiles, AStaleTemporaryIsCleared) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  dir.write("keyring.new", "left by a crash");
  const auto path = (dir.path() / "keyring").string();
  ASSERT_TRUE(run(files.write(path, bytes("fresh"), false)).ok);
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("fresh"));
}

TEST(SystemFiles, RefusesWhatIsNotAPlainFile) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto target = dir.write("real", "content");
  const auto link = dir.path() / "link";
  std::filesystem::create_symlink(target, link);

  const auto through_link = run(files.read(link.string(), 100));
  EXPECT_FALSE(through_link.ok);
  EXPECT_NE(through_link.error.find("symlink"), std::string::npos);

  EXPECT_FALSE(run(files.read(dir.path().string(), 100)).ok);
  EXPECT_FALSE(run(files.read((dir.path() / "missing").string(), 100)).ok);
}

TEST(SystemFiles, RefusesWhatIsTooLarge) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = dir.write("big", std::string(101, 'x'));
  const auto read = run(files.read(path.string(), 100));
  EXPECT_FALSE(read.ok);
  EXPECT_NE(read.error.find("larger than 100"), std::string::npos);
  EXPECT_TRUE(run(files.read(path.string(), 101)).ok);
}

TEST(SystemFiles, MakesDirectoriesPrivate) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = dir.path() / "state" / "lugh";
  ASSERT_TRUE(run(files.make_directory(path.string())).ok);
  EXPECT_TRUE(std::filesystem::is_directory(path));
  EXPECT_EQ(mode_of(path), 0700u);
  EXPECT_TRUE(run(files.make_directory(path.string())).ok);

  const auto file = dir.write("plain", "x");
  EXPECT_FALSE(run(files.make_directory(file.string())).ok);
}

TEST(SystemFiles, AppendsTruncatesAndRemoves) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = (dir.path() / "users.log").string();

  EXPECT_FALSE(run(files.append(path, bytes("x"))).ok);
  ASSERT_TRUE(run(files.write(path, bytes("head"), false)).ok);
  ASSERT_TRUE(run(files.append(path, bytes("-one"))).ok);
  ASSERT_TRUE(run(files.append(path, bytes("-two"))).ok);
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("head-one-two"));

  ASSERT_TRUE(run(files.truncate(path, 8)).ok);
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("head-one"));

  ASSERT_TRUE(run(files.remove(path)).ok);
  EXPECT_FALSE(run(files.exists(path)));
  EXPECT_TRUE(run(files.remove(path)).ok);
  EXPECT_FALSE(run(files.truncate(path, 0)).ok);
}

TEST(SystemFiles, AppendDoesNotFollowSymlinks) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto target = dir.write("real", "content");
  const auto link = dir.path() / "link";
  std::filesystem::create_symlink(target, link);
  EXPECT_FALSE(run(files.append(link.string(), bytes("x"))).ok);
  EXPECT_EQ(run(files.read(target.string(), 100)).value, bytes("content"));
}

// Dannan's durable writes make the directories a file needs.
TEST(SystemFiles, AWriteMakesTheDirectoriesItNeeds) {
  TempDirectory dir;
  SystemFiles files(test_pool());
  const auto path = (dir.path() / "missing" / "keyring").string();
  ASSERT_TRUE(run(files.write(path, bytes("x"), false)).ok);
  EXPECT_EQ(run(files.read(path, 100)).value, bytes("x"));
}

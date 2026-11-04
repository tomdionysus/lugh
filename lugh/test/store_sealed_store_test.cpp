//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/identity/crypto.h"
#include "dannan/net/codec.h"
#include "lugh/core/codec.h"
#include "lugh/store/sealed_store.h"
#include "lugh/system/system_files.h"
#include "lugh/test/fixtures/hex.h"
#include "lugh/test/fixtures/run.h"
#include "lugh/test/fixtures/sealed_store_rig.h"
#include "lugh/test/fixtures/temp_directory.h"

using lugh::byte_span;
using lugh::store::StoreError;
using lugh::store::TableSpec;

namespace {

std::vector<TableSpec> specs() { return {TableSpec{"users", {name_index()}}, TableSpec{"groups", {}}}; }

std::size_t header_length(const lugh::Bytes& file) { return lugh::store::decode_file_header(file)->length; }

}  // namespace

TEST(SealedStore, EverythingSurvivesAReopen) {
  SealedStoreRig rig(specs());
  {
    auto store = rig.open_ok();
    run(store->put("users", "u1", secure("alice:one")));
    run(store->put("users", "u1", secure("alice:two")));
    run(store->put("users", "u2", secure("bob:x")));
    run(store->remove("users", "u2"));
    run(store->put("groups", "g1", secure("admins")));
  }

  auto store = rig.open_ok();
  const auto alice = run(store->get("users", "u1"));
  ASSERT_TRUE(alice);
  EXPECT_EQ(alice->version, 2u);
  EXPECT_EQ(text(alice->value), "alice:two");
  EXPECT_EQ(run(store->find("users", "name", "alice"))->key, "u1");
  EXPECT_FALSE(run(store->find("users", "name", "bob")));
  EXPECT_TRUE(run(store->removed("users", "u2")));
  EXPECT_EQ(run(store->put("users", "u2", secure("bob:again"))).error, StoreError::removed);
  EXPECT_EQ(text(run(store->get("groups", "g1"))->value), "admins");
  EXPECT_EQ(run(store->put("users", "u1", secure("alice:three"))).version, 3u);
}

TEST(SealedStore, TheFirstOpenMakesAndSavesDataKeys) {
  SealedStoreRig rig(specs());
  EXPECT_FALSE(run(rig.files->exists("/state/keyring")));
  rig.open_ok();
  ASSERT_TRUE(run(rig.files->exists("/state/keyring")));

  const auto keyring = lugh::keys::Keyring::open(*rig.files->get("/state/keyring"), lugh::Bytes(32, 0x5a));
  ASSERT_TRUE(keyring.ok) << keyring.error;
  ASSERT_NE(keyring.value.current("users"), nullptr);
  ASSERT_NE(keyring.value.current("groups"), nullptr);
  EXPECT_EQ(keyring.value.current("users")->epoch, 1u);
}

TEST(SealedStore, NothingIsInTheClearOnDisk) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  run(store->put("users", "user-key-1", secure("alice:hunter2")));
  const auto file = rig.file("users");
  for (const std::string needle : {"alice", "hunter2", "user-key-1"}) {
    EXPECT_EQ(std::search(file.begin(), file.end(), needle.begin(), needle.end()), file.end()) << needle;
  }
}

TEST(SealedStore, AFailedWriteIsCutBackAndChangesNothing) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  run(store->put("users", "u1", secure("alice:x")));
  const auto before = rig.file("users");

  rig.files->tear_next_append = 7;
  const auto failed = run(store->put("users", "u1", secure("alice:y")));
  EXPECT_EQ(failed.error, StoreError::failed);
  EXPECT_EQ(rig.file("users"), before);
  EXPECT_EQ(text(run(store->get("users", "u1"))->value), "alice:x");

  // And the table goes on.
  EXPECT_EQ(run(store->put("users", "u1", secure("alice:z"))).version, 2u);
  auto reopened = rig.open_ok();
  EXPECT_EQ(text(run(reopened->get("users", "u1"))->value), "alice:z");
}

TEST(SealedStore, ATornWriteThatCannotBeCutIsCutAtTheNextOpen) {
  SealedStoreRig rig(specs());
  {
    auto store = rig.open_ok();
    run(store->put("users", "u1", secure("alice:x")));
    rig.files->tear_next_append = 40;
    rig.files->fail_truncate = true;
    EXPECT_EQ(run(store->put("users", "u2", secure("bob:y"))).error, StoreError::failed);

    // Nothing more goes after a tail it could not cut.
    rig.files->fail_truncate = false;
    const auto refused = run(store->put("users", "u3", secure("carol:z")));
    EXPECT_EQ(refused.error, StoreError::failed);
    EXPECT_NE(refused.message.find("restart"), std::string::npos);
  }

  auto store = rig.open_ok();
  EXPECT_NE(rig.logger->text().find("cut a torn tail"), std::string::npos);
  EXPECT_EQ(text(run(store->get("users", "u1"))->value), "alice:x");
  EXPECT_FALSE(run(store->get("users", "u2")));
  EXPECT_TRUE(run(store->put("users", "u2", secure("bob:again"))).ok());

  auto again = rig.open_ok();
  EXPECT_EQ(text(run(again->get("users", "u2"))->value), "bob:again");
}

TEST(SealedStore, EveryTornLengthRecoversToAPrefix) {
  SealedStoreRig base(specs());
  {
    auto store = base.open_ok();
    run(store->put("groups", "a", secure("1")));
    run(store->put("groups", "b", secure("2")));
    run(store->put("groups", "a", secure("3")));
  }
  const auto file = base.file("groups");

  for (std::size_t length = header_length(file); length <= file.size(); ++length) {
    SealedStoreRig rig(specs());
    rig.files = base.files;
    rig.keyrings = base.keyrings;
    const auto saved = rig.file("groups");
    rig.file_set("groups", lugh::Bytes(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(length)));

    auto store = rig.open();
    ASSERT_TRUE(store.ok) << length << ": " << store.error;
    // What survives is always what was written, in order, up to some frame.
    const auto a = run(store.value->get("groups", "a"));
    const auto b = run(store.value->get("groups", "b"));
    if (b) EXPECT_TRUE(a);
    if (a && a->version == 2) EXPECT_EQ(text(a->value), "3");
    if (a && a->version == 1) EXPECT_EQ(text(a->value), "1");
    rig.file_set("groups", saved);
  }
}

TEST(SealedStore, DamageInTheMiddleStopsTheOpen) {
  SealedStoreRig rig(specs());
  {
    auto store = rig.open_ok();
    run(store->put("users", "u1", secure("alice:x")));
    run(store->put("users", "u2", secure("bob:y")));
  }
  auto file = rig.file("users");
  file[header_length(file) + 40] ^= 0x10;
  rig.file_set("users", file);

  const auto opened = rig.open();
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("damaged"), std::string::npos);
  EXPECT_NE(opened.error.find("users.log"), std::string::npos);
  // And the file is left as it was, for whoever restores it.
  EXPECT_EQ(rig.file("users"), file);
}

TEST(SealedStore, AnotherTablesLogIsRefused) {
  SealedStoreRig rig(specs());
  {
    auto store = rig.open_ok();
    run(store->put("users", "u1", secure("alice:x")));
  }
  rig.file_set("groups", rig.file("users"));
  const auto opened = rig.open();
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("table users's"), std::string::npos);
}

TEST(SealedStore, AnotherKeyringIsRefusedNotTruncated) {
  SealedStoreRig rig(specs());
  {
    auto store = rig.open_ok();
    run(store->put("users", "u1", secure("alice:x")));
  }
  const auto file = rig.file("users");

  // The same tables under a keyring made afresh: its keys are not these.
  SealedStoreRig stranger(specs());
  stranger.file_set("users", file);
  const auto opened = stranger.open();
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("does not open"), std::string::npos);
  EXPECT_EQ(stranger.file("users"), file);
}

TEST(SealedStore, CompactionKeepsWhatIsLiveAndTheTombstones) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  for (int i = 0; i < 20; ++i) run(store->put("users", "u1", secure("alice:" + std::to_string(i))));
  run(store->put("users", "u2", secure("bob:x")));
  run(store->remove("users", "u2"));

  const auto before = store->usage("users").value();
  EXPECT_GT(before.superseded, 0u);
  ASSERT_TRUE(run(store->compact("users")).ok);
  const auto after = store->usage("users").value();
  EXPECT_EQ(after.superseded, 0u);
  EXPECT_LT(after.bytes, before.bytes);
  EXPECT_EQ(after.bytes, rig.file("users").size());

  EXPECT_EQ(run(store->get("users", "u1"))->version, 20u);
  EXPECT_TRUE(run(store->removed("users", "u2")));
  EXPECT_TRUE(run(store->put("users", "u3", secure("carol:"))).ok());

  auto reopened = rig.open_ok();
  EXPECT_EQ(text(run(reopened->get("users", "u1"))->value), "alice:19");
  EXPECT_EQ(run(reopened->get("users", "u1"))->version, 20u);
  EXPECT_TRUE(run(reopened->removed("users", "u2")));
  EXPECT_EQ(run(reopened->put("users", "u2", secure("bob:"))).error, StoreError::removed);
  EXPECT_EQ(text(run(reopened->get("users", "u3"))->value), "carol:");
}

TEST(SealedStore, ACompactionThatFailsLeavesTheOldLog) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  run(store->put("users", "u1", secure("alice:1")));
  run(store->put("users", "u1", secure("alice:2")));
  const auto before = rig.file("users");

  rig.files->fail_writes = true;
  EXPECT_FALSE(run(store->compact("users")).ok);
  rig.files->fail_writes = false;
  EXPECT_EQ(rig.file("users"), before);
  EXPECT_TRUE(run(store->put("users", "u1", secure("alice:3"))).ok());
  EXPECT_EQ(text(run(rig.open_ok()->get("users", "u1"))->value), "alice:3");
}

TEST(SealedStore, CompactionRunsByItselfWhenMostIsSuperseded) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  const std::string value(64 * 1024, 'v');
  for (int i = 0; i < 40; ++i) run(store->put("groups", "big", secure(value + std::to_string(i))));

  const auto usage = store->usage("groups").value();
  EXPECT_LT(usage.bytes, lugh::store::SealedStore::kCompactAfterBytes + 2 * value.size());
  EXPECT_NE(rig.logger->text().find("compacted"), std::string::npos);
  EXPECT_EQ(text(run(rig.open_ok()->get("groups", "big"))->value), value + "39");
}

TEST(SealedStore, RotationResealsUnderTheNewEpoch) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  run(store->put("users", "u1", secure("alice:x")));
  run(store->put("users", "u2", secure("bob:y")));
  run(store->remove("users", "u2"));

  ASSERT_TRUE(run(store->rotate("users")).ok);
  EXPECT_EQ(store->usage("users")->epoch, 2u);

  // The header and every frame under epoch 2: a frame's epoch is the four bytes after its
  // magic.
  const auto file = rig.file("users");
  const auto header = lugh::store::decode_file_header(file);
  ASSERT_TRUE(header);
  EXPECT_EQ(header->header.epoch, 2u);
  std::size_t frames = 0;
  for (std::size_t at = header->length; at < file.size();) {
    dannan::net::Reader reader(std::span(file).subspan(at + 4, 8));
    EXPECT_EQ(reader.u32(), 2u);
    at += lugh::store::kFrameHeaderBytes + reader.u32();
    ++frames;
  }
  EXPECT_EQ(frames, 2u);

  run(store->put("users", "u3", secure("carol:z")));
  auto reopened = rig.open_ok();
  EXPECT_EQ(text(run(reopened->get("users", "u1"))->value), "alice:x");
  EXPECT_EQ(text(run(reopened->get("users", "u3"))->value), "carol:z");
  EXPECT_TRUE(run(reopened->removed("users", "u2")));
  EXPECT_EQ(reopened->usage("users")->epoch, 2u);
}

TEST(SealedStore, RotationNeedsTheKeyringSaved) {
  SealedStoreRig rig(specs());
  auto store = rig.open_ok();
  run(store->put("users", "u1", secure("alice:x")));

  rig.files->fail_writes = true;
  EXPECT_FALSE(run(store->rotate("users")).ok);
  rig.files->fail_writes = false;
  EXPECT_EQ(store->usage("users")->epoch, 1u);
  EXPECT_TRUE(run(store->put("users", "u1", secure("alice:y"))).ok());
  EXPECT_EQ(text(run(rig.open_ok()->get("users", "u1"))->value), "alice:y");
}

TEST(SealedStore, RefusesBadTableSpecs) {
  SealedStoreRig twice({TableSpec{"users", {}}, TableSpec{"users", {}}});
  EXPECT_FALSE(twice.open().ok);
  SealedStoreRig bad_name({TableSpec{"Users", {}}});
  EXPECT_FALSE(bad_name.open().ok);
}

// On a real disk, through SystemFiles: garbage after the last frame, as a crash on a
// filesystem that extended the file before writing it leaves.
TEST(SealedStore, OnDiskATornTailIsCut) {
  TempDirectory dir;
  auto files = std::make_shared<lugh::system::SystemFiles>(test_pool());
  auto logger = std::make_shared<RecordingSink>();
  auto keyrings = std::make_shared<lugh::keys::KeyringManager>(logger, files, std::make_shared<ScriptedConsole>(), std::make_shared<MapEnvironment>(),
                                                               dir.path().string(), test_pool());
  lugh::keys::KeyringHeader header;
  header.id = dannan::identity::random_bytes(16);
  const auto master = lugh::Bytes(32, 0x11);
  const auto store_directory = (dir.path() / "store").string();

  {
    auto keyring = lugh::keys::Keyring::create(header, master).value;
    auto store = run(lugh::store::SealedStore::open(logger, files, keyrings, keyring, store_directory, specs()));
    ASSERT_TRUE(store.ok) << store.error;
    run(store.value->put("users", "u1", secure("alice:x")));
  }

  const auto path = store_directory + "/users.log";
  const auto good = run(files->read(path, 1 << 20)).value;
  ASSERT_TRUE(run(files->append(path, lugh::Bytes(5000, 0))).ok);

  auto keyring = lugh::keys::Keyring::open(run(files->read(dir.path().string() + "/keyring", 1 << 20)).value, master).value;
  auto store = run(lugh::store::SealedStore::open(logger, files, keyrings, keyring, store_directory, specs()));
  ASSERT_TRUE(store.ok) << store.error;
  EXPECT_EQ(text(run(store.value->get("users", "u1"))->value), "alice:x");
  EXPECT_EQ(run(files->read(path, 1 << 20)).value, good);
}

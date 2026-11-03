//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The store's rules, run against SealedStore and the MemoryStore fake alike, so a test
// written against the fake means what it says.

#include <gtest/gtest.h>

#include <thread>

#include "fakes/memory_store.h"
#include "helpers/run.h"
#include "helpers/sealed_store_rig.h"

using lugh::byte_span;
using lugh::store::Store;
using lugh::store::StoreError;
using lugh::store::TableSpec;

namespace {

std::vector<TableSpec> specs() { return {TableSpec{"users", {name_index()}}, TableSpec{"groups", {}}}; }

class SealedMaker {
 public:
  std::shared_ptr<Store> make() { return _rig.open_ok(); }

 private:
  SealedStoreRig _rig{specs()};
};

class MemoryMaker {
 public:
  std::shared_ptr<Store> make() { return std::make_shared<MemoryStore>(specs()); }
};

template <typename Maker>
class StoreContract : public ::testing::Test {
 protected:
  void SetUp() override { store = maker.make(); }
  Maker maker;
  std::shared_ptr<Store> store;
};

using Makers = ::testing::Types<SealedMaker, MemoryMaker>;
TYPED_TEST_SUITE(StoreContract, Makers);

}  // namespace

TYPED_TEST(StoreContract, PutThenGet) {
  const auto written = run(this->store->put("users", "u1", secure("alice:admin")));
  ASSERT_TRUE(written.ok()) << written.message;
  EXPECT_EQ(written.version, 1u);

  const auto record = run(this->store->get("users", "u1"));
  ASSERT_TRUE(record);
  EXPECT_EQ(record->key, "u1");
  EXPECT_EQ(record->version, 1u);
  EXPECT_EQ(text(record->value), "alice:admin");
}

TYPED_TEST(StoreContract, EachPutIsTheNextVersion) {
  run(this->store->put("users", "u1", secure("alice:one")));
  EXPECT_EQ(run(this->store->put("users", "u1", secure("alice:two"))).version, 2u);
  EXPECT_EQ(run(this->store->put("users", "u1", secure("alice:three"))).version, 3u);
  EXPECT_EQ(text(run(this->store->get("users", "u1"))->value), "alice:three");
}

TYPED_TEST(StoreContract, AbsentThingsAreAbsent) {
  EXPECT_FALSE(run(this->store->get("users", "nobody")));
  EXPECT_FALSE(run(this->store->get("nothing", "u1")));
  EXPECT_FALSE(run(this->store->removed("users", "nobody")));
  EXPECT_TRUE(run(this->store->list("nothing")).empty());
  EXPECT_EQ(run(this->store->put("nothing", "u1", secure("x"))).error, StoreError::not_found);
}

TYPED_TEST(StoreContract, ExpectedZeroMeansNew) {
  EXPECT_TRUE(run(this->store->put("users", "u1", secure("a:"), 0)).ok());
  const auto again = run(this->store->put("users", "u1", secure("b:"), 0));
  EXPECT_EQ(again.error, StoreError::conflict);
  EXPECT_EQ(text(run(this->store->get("users", "u1"))->value), "a:");
}

TYPED_TEST(StoreContract, ExpectedVersionIsChecked) {
  run(this->store->put("users", "u1", secure("a:")));
  EXPECT_EQ(run(this->store->put("users", "u1", secure("b:"), 1)).version, 2u);
  EXPECT_EQ(run(this->store->put("users", "u1", secure("c:"), 1)).error, StoreError::conflict);
  EXPECT_EQ(run(this->store->put("users", "u1", secure("c:"), 3)).error, StoreError::conflict);
  EXPECT_EQ(text(run(this->store->get("users", "u1"))->value), "b:");
}

TYPED_TEST(StoreContract, RemovalIsFinal) {
  run(this->store->put("users", "u1", secure("alice:")));
  const auto removed = run(this->store->remove("users", "u1"));
  ASSERT_TRUE(removed.ok()) << removed.message;
  EXPECT_EQ(removed.version, 2u);

  EXPECT_FALSE(run(this->store->get("users", "u1")));
  EXPECT_TRUE(run(this->store->removed("users", "u1")));
  EXPECT_TRUE(run(this->store->list("users")).empty());
  EXPECT_EQ(run(this->store->put("users", "u1", secure("alice:"))).error, StoreError::removed);
  EXPECT_EQ(run(this->store->remove("users", "u1")).error, StoreError::removed);
}

TYPED_TEST(StoreContract, RemoveNeedsARecord) {
  EXPECT_EQ(run(this->store->remove("users", "nobody")).error, StoreError::not_found);
  run(this->store->put("users", "u1", secure("a:")));
  EXPECT_EQ(run(this->store->remove("users", "u1", 7)).error, StoreError::conflict);
  EXPECT_TRUE(run(this->store->remove("users", "u1", 1)).ok());
}

TYPED_TEST(StoreContract, ListIsInKeyOrder) {
  run(this->store->put("groups", "c", secure("3")));
  run(this->store->put("groups", "a", secure("1")));
  run(this->store->put("groups", "b", secure("2")));
  run(this->store->remove("groups", "b"));

  const auto all = run(this->store->list("groups"));
  ASSERT_EQ(all.size(), 2u);
  EXPECT_EQ(all[0].key, "a");
  EXPECT_EQ(all[1].key, "c");
}

TYPED_TEST(StoreContract, TablesAreSeparate) {
  run(this->store->put("users", "k", secure("u:")));
  run(this->store->put("groups", "k", secure("g")));
  EXPECT_EQ(text(run(this->store->get("users", "k"))->value), "u:");
  EXPECT_EQ(text(run(this->store->get("groups", "k"))->value), "g");
}

TYPED_TEST(StoreContract, AnIndexFindsTheRecord) {
  run(this->store->put("users", "u1", secure("alice:x")));
  run(this->store->put("users", "u2", secure("bob:y")));

  const auto alice = run(this->store->find("users", "name", "alice"));
  ASSERT_TRUE(alice);
  EXPECT_EQ(alice->key, "u1");
  EXPECT_FALSE(run(this->store->find("users", "name", "carol")));
  EXPECT_FALSE(run(this->store->find("users", "email", "alice")));
}

TYPED_TEST(StoreContract, AnIndexIsUnique) {
  run(this->store->put("users", "u1", secure("alice:x")));
  const auto clash = run(this->store->put("users", "u2", secure("alice:y")));
  EXPECT_EQ(clash.error, StoreError::duplicate);
  EXPECT_FALSE(run(this->store->get("users", "u2")));

  // The record that holds the value may keep it.
  EXPECT_TRUE(run(this->store->put("users", "u1", secure("alice:z"))).ok());
}

TYPED_TEST(StoreContract, AnIndexFollowsTheValue) {
  run(this->store->put("users", "u1", secure("alice:x")));
  run(this->store->put("users", "u1", secure("alicia:x")));
  EXPECT_FALSE(run(this->store->find("users", "name", "alice")));
  EXPECT_EQ(run(this->store->find("users", "name", "alicia"))->key, "u1");

  // Freed, so another record can have it.
  EXPECT_TRUE(run(this->store->put("users", "u2", secure("alice:y"))).ok());

  run(this->store->remove("users", "u1"));
  EXPECT_FALSE(run(this->store->find("users", "name", "alicia")));
  EXPECT_TRUE(run(this->store->put("users", "u3", secure("alicia:z"))).ok());
}

TYPED_TEST(StoreContract, BoundsAreKept) {
  EXPECT_EQ(run(this->store->put("users", "", secure("x"))).error, StoreError::invalid);
  EXPECT_EQ(run(this->store->put("users", std::string(256, 'k'), secure("x"))).error, StoreError::invalid);
  EXPECT_TRUE(run(this->store->put("users", std::string(255, 'k'), secure("x"))).ok());

  const lugh::SecureBytes big(lugh::store::kMostValueBytes + 1, 'v');
  EXPECT_EQ(run(this->store->put("groups", "big", big)).error, StoreError::invalid);
  const lugh::SecureBytes most(lugh::store::kMostValueBytes, 'v');
  EXPECT_TRUE(run(this->store->put("groups", "most", most)).ok());
  EXPECT_EQ(run(this->store->get("groups", "most"))->value.size(), lugh::store::kMostValueBytes);

  EXPECT_TRUE(run(this->store->put("groups", "empty", {})).ok());
  EXPECT_TRUE(run(this->store->get("groups", "empty"))->value.empty());
}

TYPED_TEST(StoreContract, ConcurrentWritersAllLand) {
  std::vector<std::thread> writers;
  for (int t = 0; t < 4; ++t) {
    writers.emplace_back([this, t] {
      for (int i = 0; i < 25; ++i) {
        const auto key = "t" + std::to_string(t) + "-" + std::to_string(i);
        run(this->store->put("groups", key, secure(key)));
        run(this->store->get("groups", key));
      }
    });
  }
  for (auto& writer : writers) writer.join();
  EXPECT_EQ(run(this->store->list("groups")).size(), 100u);
}

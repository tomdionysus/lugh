//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "audit/audit_log.h"

#include <gtest/gtest.h>

#include "fakes/manual_clock.h"
#include "fakes/memory_store.h"
#include "helpers/run.h"
#include "mocks/logger_mock.h"

using lugh::audit::AuditLog;
using lugh::audit::Event;

namespace {

class AuditLogTest : public ::testing::Test {
 protected:
  std::shared_ptr<AuditLog> open() {
    auto opened = run(AuditLog::open(logger, store, clock));
    EXPECT_TRUE(opened.ok) << opened.error;
    return opened.value;
  }

  std::shared_ptr<MockLogger> logger = std::make_shared<MockLogger>();
  std::shared_ptr<MemoryStore> store = std::make_shared<MemoryStore>(std::vector<lugh::store::TableSpec>{{"audit", {}}});
  std::shared_ptr<ManualClock> clock = std::make_shared<ManualClock>();
};

}  // namespace

TEST_F(AuditLogTest, EachEntryCarriesTheHashOfTheOneBefore) {
  auto log = open();
  ASSERT_TRUE(run(log->record(Event{"user.create", "admin", "u1", "192.0.2.1", "person"})).ok);
  clock->advance(std::chrono::seconds(5));
  ASSERT_TRUE(run(log->record(Event{"user.disable", "admin", "u1", "192.0.2.1", ""})).ok);

  const auto entries = run(log->entries(1, 10));
  ASSERT_EQ(entries.size(), 2u);
  EXPECT_EQ(entries[0].sequence, 1u);
  EXPECT_EQ(entries[0].previous, lugh::audit::Hash{});
  EXPECT_EQ(entries[0].time, 1792281600u);
  EXPECT_EQ(entries[0].event.actor, "admin");
  EXPECT_EQ(entries[0].event.source, "192.0.2.1");
  EXPECT_EQ(entries[1].previous, entries[0].hash);
  EXPECT_EQ(entries[1].time, 1792281605u);
  EXPECT_NE(entries[1].hash, entries[0].hash);

  const auto verified = run(log->verify());
  ASSERT_TRUE(verified.ok) << verified.error;
  EXPECT_EQ(verified.value, 2u);
}

TEST_F(AuditLogTest, OpeningAgainCarriesOn) {
  run(open()->record(Event{"a", "x", "", "", ""}));
  run(open()->record(Event{"b", "x", "", "", ""}));
  auto log = open();
  run(log->record(Event{"c", "x", "", "", ""}));

  EXPECT_EQ(log->size(), 3u);
  const auto entries = run(log->entries(1, 10));
  ASSERT_EQ(entries.size(), 3u);
  EXPECT_EQ(entries[2].event.action, "c");
  EXPECT_TRUE(run(log->verify()).ok);
}

TEST_F(AuditLogTest, KeysSortInSequence) {
  EXPECT_EQ(AuditLog::key(1), "00000000000000000001");
  EXPECT_LT(AuditLog::key(9), AuditLog::key(10));
}

TEST_F(AuditLogTest, AnAlteredEntryIsFound) {
  auto log = open();
  for (const auto* action : {"a", "b", "c"}) run(log->record(Event{action, "x", "", "", ""}));

  // Rewritten with the keys in hand: the record opens, the chain does not hold.
  auto entry = *AuditLog::decode(store->get_now("audit", AuditLog::key(2))->value);
  entry.event.actor = "someone else";
  store->put_now("audit", AuditLog::key(2), AuditLog::encode(entry));

  const auto verified = run(log->verify());
  ASSERT_FALSE(verified.ok);
  EXPECT_EQ(verified.error, "audit entry 2 has been altered");
}

TEST_F(AuditLogTest, ARewrittenChainIsFoundWhereItJoins) {
  auto log = open();
  for (const auto* action : {"a", "b", "c"}) run(log->record(Event{action, "x", "", "", ""}));

  // Entry 2 rewritten with a hash of its own that is right, made the way the log makes
  // one, by a second log fed the same first entry: entry 3 no longer follows it.
  auto entry = *AuditLog::decode(store->get_now("audit", AuditLog::key(2))->value);
  entry.event.actor = "someone else";
  auto other_store = std::make_shared<MemoryStore>(std::vector<lugh::store::TableSpec>{{"audit", {}}});
  auto other = run(AuditLog::open(logger, other_store, clock)).value;
  run(other->record(Event{"a", "x", "", "", ""}));
  run(other->record(entry.event));
  store->put_now("audit", AuditLog::key(2), other_store->get_now("audit", AuditLog::key(2))->value);

  const auto verified = run(log->verify());
  ASSERT_FALSE(verified.ok);
  EXPECT_EQ(verified.error, "audit entry 3 does not follow the one before");
}

TEST_F(AuditLogTest, AMissingEntryIsFound) {
  auto log = open();
  for (const auto* action : {"a", "b", "c"}) run(log->record(Event{action, "x", "", "", ""}));
  store->remove_now("audit", AuditLog::key(2));

  const auto verified = run(log->verify());
  ASSERT_FALSE(verified.ok);
  EXPECT_EQ(verified.error, "audit entry 2 is missing");
}

TEST_F(AuditLogTest, LongFieldsAreCutNotRefused) {
  auto log = open();
  ASSERT_TRUE(run(log->record(Event{std::string(1000, 'a'), "x", "", "", std::string(5000, 'd')})).ok);
  const auto entry = run(log->entries(1, 1)).at(0);
  EXPECT_EQ(entry.event.action.size(), AuditLog::kMostFieldBytes);
  EXPECT_EQ(entry.event.detail.size(), AuditLog::kMostDetailBytes);
  EXPECT_TRUE(run(log->verify()).ok);
}

TEST_F(AuditLogTest, AFailedWriteIsLoggedAndAnswered) {
  auto log = run(AuditLog::open(logger, std::make_shared<MemoryStore>(std::vector<lugh::store::TableSpec>{}), clock)).value;
  EXPECT_FALSE(run(log->record(Event{"user.create", "admin", "u1", "", ""})).ok);
  EXPECT_NE(logger->text().find("cannot record user.create for u1"), std::string::npos);
  EXPECT_EQ(log->size(), 0u);
}

TEST_F(AuditLogTest, DecodeRefusesAnythingElse) {
  auto log = open();
  run(log->record(Event{"a", "x", "y", "z", "w"}));
  const auto value = store->get_now("audit", AuditLog::key(1))->value;
  ASSERT_TRUE(AuditLog::decode(value));
  for (std::size_t length = 0; length < value.size(); ++length) EXPECT_FALSE(AuditLog::decode(std::span(value).first(length))) << length;
  auto longer = lugh::Bytes(value.begin(), value.end());
  longer.push_back(0);
  EXPECT_FALSE(AuditLog::decode(longer));
}

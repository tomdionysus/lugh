// What async means for the store: while one write waits on the disk, nothing else waits
// with it. A held append on one table leaves reads of that table, and writes to another,
// to finish; the held write is not seen until it is acknowledged; and a second writer on
// the same table waits its turn without a thread. One io_context, one thread, polled.

#include <gtest/gtest.h>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <set>

#include "fakes/fixed_random.h"
#include "fakes/map_environment.h"
#include "fakes/memory_files.h"
#include "fakes/scripted_console.h"
#include "helpers/pools.h"
#include "helpers/run.h"
#include "helpers/sealed_store_rig.h"
#include "mocks/logger_mock.h"
#include "store/sealed_store.h"

namespace {

// MemoryFiles whose appends to one path wait, suspended, until released: a slow disk.
class HeldFiles : public MemoryFiles {
 public:
  explicit HeldFiles(lugh::Executor executor) : _gate(executor, std::chrono::steady_clock::time_point::max()) {}

  lugh::Task<lugh::Status> append(std::string path, lugh::Bytes data) override {
    if (path == held) {
      ++waiting;
      co_await _gate.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    }
    co_return co_await MemoryFiles::append(std::move(path), std::move(data));
  }

  void release() {
    held.clear();
    _gate.cancel();
  }

  std::string held;
  int waiting = 0;

 private:
  boost::asio::steady_timer _gate;
};

}  // namespace

TEST(AsyncStore, AWriteWaitingOnTheDiskHoldsNothingElseUp) {
  boost::asio::io_context io;
  auto files = std::make_shared<HeldFiles>(io.get_executor());
  auto logger = std::make_shared<MockLogger>();
  auto random = std::make_shared<FixedRandom>();
  auto keyrings = std::make_shared<lugh::keys::KeyringManager>(logger, files, random, std::make_shared<ScriptedConsole>(), std::make_shared<MapEnvironment>(),
                                                               "/state", test_pool());
  lugh::keys::KeyringHeader header;
  header.id = random->bytes(16);
  auto keyring = lugh::keys::Keyring::create(header, lugh::Bytes(32, 0x5a)).value;
  auto opened = run(lugh::store::SealedStore::open(logger, files, random, keyrings, keyring, "/state/store",
                                                   {lugh::store::TableSpec{"users", {name_index()}}, lugh::store::TableSpec{"groups", {}}}));
  ASSERT_TRUE(opened.ok) << opened.error;
  auto store = opened.value;
  ASSERT_TRUE(run(store->put("users", "u0", secure("zero:"))).ok());

  files->held = "/state/store/users.log";
  std::vector<std::string> done;
  const auto spawn = [&](std::string name, lugh::Task<lugh::store::Write> write) {
    boost::asio::co_spawn(
        io,
        [&done, name = std::move(name), write = std::move(write)]() mutable -> lugh::Task<void> {
          const auto written = co_await std::move(write);
          done.push_back(name + (written.ok() ? " ok" : " failed"));
        },
        boost::asio::detached);
  };

  spawn("users u1", store->put("users", "u1", secure("alice:")));
  spawn("users u2", store->put("users", "u2", secure("bob:")));
  spawn("groups g1", store->put("groups", "g1", secure("admins")));
  io.poll();

  // The first users write is at its append, the second behind it on the table's lock; the
  // groups write went straight through.
  EXPECT_EQ(files->waiting, 1);
  EXPECT_EQ(done, std::vector<std::string>{"groups g1 ok"});

  // Reads of the held table answer meanwhile, and do not see what is not yet durable.
  EXPECT_EQ(text(run(store->get("users", "u0"))->value), "zero:");
  EXPECT_FALSE(run(store->get("users", "u1")));
  EXPECT_FALSE(run(store->find("users", "name", "alice")));

  files->release();
  io.run();
  EXPECT_EQ(done, (std::vector<std::string>{"groups g1 ok", "users u1 ok", "users u2 ok"}));
  EXPECT_EQ(text(run(store->get("users", "u1"))->value), "alice:");
  EXPECT_EQ(text(run(store->get("users", "u2"))->value), "bob:");
}

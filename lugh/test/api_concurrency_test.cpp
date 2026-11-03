//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The API as it runs in the service: handlers as coroutines on a pool of threads, many at
// once, suspending on the store's locks and the hashing pool. Under the tsan preset this is
// where a race in the store, the directory or the audit log would show.

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>
#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>

#include "lugh/test/fixtures/api_rig.h"

using lugh::http::verb;

namespace {

// Requests sent from one thread, answered on the pool's, gathered here.
class Responses {
 public:
  void send(const lugh::http::HttpMiddleware& middleware, verb method, const std::string& target, const std::string& body) {
    lugh::http::HttpRequest request{method, target, 11};
    request.set(lugh::http::field::authorization, std::string("Bearer ") + ApiRig::kToken);
    request.body() = body;
    request.prepare_payload();
    auto response = std::make_shared<lugh::http::HttpResponse>();
    {
      std::lock_guard<std::mutex> lock(_mutex);
      ++_sent;
    }
    middleware(request, "192.0.2.50", response, [this, response](bool) {
      std::lock_guard<std::mutex> lock(_mutex);
      _statuses.push_back(response->result_int());
      _threads.insert(std::this_thread::get_id());
      _changed.notify_all();
    });
  }

  std::vector<unsigned> wait() {
    std::unique_lock<std::mutex> lock(_mutex);
    _changed.wait_for(lock, std::chrono::seconds(30), [this] { return _statuses.size() == _sent; });
    return _statuses;
  }

  bool answered_elsewhere() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _threads.count(std::this_thread::get_id()) == 0;
  }

 private:
  mutable std::mutex _mutex;
  std::condition_variable _changed;
  std::size_t _sent = 0;
  std::vector<unsigned> _statuses;
  std::set<std::thread::id> _threads;
};

class Concurrency : public ::testing::Test {
 protected:
  void SetUp() override {
    router = std::make_shared<lugh::http::Router>(pool.get_executor(),
                                                  std::make_shared<lugh::http::Throttle>(rig.clock, lugh::http::RateLimits{{0, 0}, {0, 0}}), rig.callers, 1000);
    rig.users.register_routes(*router);
    rig.groups.register_routes(*router);
  }

  void TearDown() override { pool.join(); }

  ApiRig rig;
  boost::asio::thread_pool pool{4};
  std::shared_ptr<lugh::http::Router> router;
};

}  // namespace

TEST_F(Concurrency, ManyWritersAtOnce) {
  Responses responses;
  const auto middleware = router->middleware("/api");
  for (int i = 0; i < 64; ++i) {
    responses.send(middleware, verb::post, "/api/v1/users",
                   R"({"name":"user)" + std::to_string(i) + R"(","email":"user)" + std::to_string(i) + R"(@example.com"})");
  }
  const auto statuses = responses.wait();
  ASSERT_EQ(statuses.size(), 64u);
  for (const auto status : statuses) EXPECT_EQ(status, 201u);
  EXPECT_TRUE(responses.answered_elsewhere());
  EXPECT_EQ(run(rig.directory->users()).size(), 64u);

  const auto verified = run(rig.audit->verify());
  ASSERT_TRUE(verified.ok) << verified.error;
  EXPECT_EQ(verified.value, 64u);
}

TEST_F(Concurrency, OneNameOneWinner) {
  Responses responses;
  const auto middleware = router->middleware("/api");
  for (int i = 0; i < 32; ++i) {
    responses.send(middleware, verb::post, "/api/v1/users", R"({"name":"alice","email":"alice)" + std::to_string(i) + R"(@example.com"})");
  }
  const auto statuses = responses.wait();
  ASSERT_EQ(statuses.size(), 32u);
  EXPECT_EQ(std::count(statuses.begin(), statuses.end(), 201u), 1);
  EXPECT_EQ(std::count(statuses.begin(), statuses.end(), 409u), 31);
  EXPECT_EQ(run(rig.directory->users()).size(), 1u);
}

TEST_F(Concurrency, RacingAddsAreOneMembership) {
  const auto alice = rig.made_user("alice");
  const auto group = run(rig.directory->create_group(rig.admin, "staff", "")).value;
  Responses responses;
  const auto middleware = router->middleware("/api");
  for (int i = 0; i < 16; ++i) responses.send(middleware, verb::put, "/api/v1/groups/" + group.id + "/members/" + alice, "");
  for (const auto status : responses.wait()) EXPECT_EQ(status, 204u);
  EXPECT_EQ(run(rig.directory->members(group.id)), std::vector<std::string>{alice});
  EXPECT_EQ(run(rig.directory->groups_of(alice)), std::vector<std::string>{group.id});
}

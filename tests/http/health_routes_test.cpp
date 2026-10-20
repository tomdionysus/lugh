#include "http/health_routes.h"

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/json.hpp>

#include "fakes/manual_clock.h"
#include "helpers/route_call.h"

using lugh::http::HealthRoutes;
using lugh::http::Router;
using lugh::http::Throttle;
namespace http = lugh::http;

namespace {

boost::asio::io_context io;

std::shared_ptr<Router> router_with_health() {
  auto router = std::make_shared<Router>(io.get_executor(), std::make_shared<Throttle>(std::make_shared<ManualClock>()));
  HealthRoutes health;
  health.register_routes(*router);
  return router;
}

}  // namespace

TEST(HealthRoutes, HealthIsOpenJsonSayingOkAndNothingElse) {
  const auto result = call(io, router_with_health()->middleware("/health"), http::verb::get, "/health");

  ASSERT_EQ(result.response->result(), http::status::ok);
  EXPECT_EQ(result.response->at(http::field::content_type), "application/json");
  EXPECT_EQ(result.response->at(http::field::cache_control), "no-store");

  const auto body = boost::json::parse(result.response->body()).as_object();
  EXPECT_EQ(body.at("status").as_string(), "ok");
  EXPECT_EQ(body.size(), 1u);
}

TEST(HealthRoutes, ReadyIsOpenJson) {
  const auto result = call(io, router_with_health()->middleware("/ready"), http::verb::get, "/ready");

  ASSERT_EQ(result.response->result(), http::status::ok);
  const auto body = boost::json::parse(result.response->body()).as_object();
  EXPECT_TRUE(body.at("ready").as_bool());
  EXPECT_EQ(body.size(), 1u);
}

TEST(HealthRoutes, OnlyGet) {
  const auto result = call(io, router_with_health()->middleware("/health"), http::verb::post, "/health");
  EXPECT_EQ(result.response->result(), http::status::method_not_allowed);
}

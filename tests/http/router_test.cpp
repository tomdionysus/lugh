#include "http/router.h"

#include <gtest/gtest.h>

#include <boost/json.hpp>

#include "fakes/manual_clock.h"
#include "helpers/route_call.h"

using lugh::http::RateLimits;
using lugh::http::RouteContext;
using lugh::http::Router;
using lugh::http::Throttle;
namespace http = lugh::http;

namespace {

std::string error_code(const RouteCall& result) { return std::string(boost::json::parse(result.response->body()).at("error").at("code").as_string()); }

// Each test's own router, throttle and clock, with limits loose enough not to interfere
// unless the test is about them.
struct Fixture {
  std::shared_ptr<ManualClock> clock = std::make_shared<ManualClock>();
  std::shared_ptr<Router> router;

  explicit Fixture(RateLimits limits = {{1000, 1000}}) { router = std::make_shared<Router>(std::make_shared<Throttle>(clock, limits)); }

  void ok_route(http::verb method, const std::string& pattern) {
    router->add_open(method, pattern, [](RouteContext context) {
      context.response->result(http::status::ok);
      context.response->body() = "id=" + context.parameter("id") + " from " + context.remote;
      context.done();
    });
  }
};

}  // namespace

TEST(Router, PassesOnWhatIsNotUnderItsPrefix) {
  Fixture f;
  const auto result = call(f.router->middleware("/api/"), http::verb::get, "/health");
  EXPECT_TRUE(result.passed_on);
  EXPECT_FALSE(result.answered);
}

TEST(Router, AnOpenRouteAnswers) {
  Fixture f;
  f.router->add_open(http::verb::get, "/health", [](RouteContext context) {
    context.response->body() = "ok";
    context.done();
  });

  const auto result = call(f.router->middleware("/health"), http::verb::get, "/health");
  EXPECT_TRUE(result.answered);
  EXPECT_EQ(result.response->body(), "ok");
}

TEST(Router, PathParametersAreDecodedAndTheRemoteIsPassed) {
  Fixture f;
  f.ok_route(http::verb::get, "/api/v1/apps/{id}");

  const auto result = call(f.router->middleware("/api/"), http::verb::get, "/api/v1/apps/app%5F7f3k", "203.0.113.7");
  EXPECT_EQ(result.response->body(), "id=app_7f3k from 203.0.113.7");
}

TEST(Router, QueryIsParsedAndDoesNotAffectMatching) {
  Fixture f;
  f.router->add_open(http::verb::get, "/api/v1/things", [](RouteContext context) {
    context.response->body() = context.query["a"] + "|" + context.query["b"] + "|" + std::to_string(context.query.count("c"));
    context.done();
  });

  const auto result = call(f.router->middleware("/api/"), http::verb::get, "/api/v1/things?a=1+2&b=%41&c");
  EXPECT_EQ(result.response->body(), "1 2|A|1");
}

TEST(Router, UnknownPathIs404) {
  Fixture f;
  const auto result = call(f.router->middleware("/api/"), http::verb::get, "/api/v1/nothing");
  EXPECT_EQ(result.response->result(), http::status::not_found);
  EXPECT_EQ(error_code(result), "not_found");
}

TEST(Router, KnownPathWrongMethodIs405) {
  Fixture f;
  f.ok_route(http::verb::get, "/api/v1/apps");
  const auto result = call(f.router->middleware("/api/"), http::verb::delete_, "/api/v1/apps");
  EXPECT_EQ(result.response->result(), http::status::method_not_allowed);
}

TEST(Router, OpenRoutesAreLimitedByClientAddress) {
  Fixture f(RateLimits{{2, 1}});
  f.router->add_open(http::verb::get, "/health", [](RouteContext context) { context.done(); });
  const auto middleware = f.router->middleware("/health");

  EXPECT_EQ(call(middleware, http::verb::get, "/health").response->result(), http::status::ok);
  EXPECT_EQ(call(middleware, http::verb::get, "/health").response->result(), http::status::ok);

  const auto refused = call(middleware, http::verb::get, "/health");
  EXPECT_EQ(refused.response->result(), http::status::too_many_requests);
  EXPECT_EQ(refused.response->at(http::field::retry_after), "60");

  // Another client is not held up.
  EXPECT_EQ(call(middleware, http::verb::get, "/health", "198.51.100.4").response->result(), http::status::ok);

  f.clock->advance(std::chrono::seconds(60));
  EXPECT_EQ(call(middleware, http::verb::get, "/health").response->result(), http::status::ok);
}

TEST(Router, UnknownPathsAreLimitedTooAgainstScanning) {
  Fixture f(RateLimits{{1, 1}});
  const auto middleware = f.router->middleware("/api/");

  EXPECT_EQ(call(middleware, http::verb::get, "/api/a").response->result(), http::status::not_found);
  EXPECT_EQ(call(middleware, http::verb::get, "/api/b").response->result(), http::status::too_many_requests);
}

TEST(Router, PercentDecode) {
  EXPECT_EQ(Router::percent_decode("a%40b.c"), "a@b.c");
  EXPECT_EQ(Router::percent_decode("a+b"), "a b");
  EXPECT_EQ(Router::percent_decode("100%"), "100%");
  EXPECT_EQ(Router::percent_decode("%zz"), "%zz");
}

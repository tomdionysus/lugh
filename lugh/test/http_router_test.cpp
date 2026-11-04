//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/json.hpp>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/http/router.h"
#include "lugh/test/fixtures/route_call.h"

using lugh::http::RateLimits;
using lugh::http::RouteContext;
using lugh::http::Router;
using lugh::http::Throttle;
namespace http = lugh::http;

namespace {

std::string error_code(const RouteCall& result) { return std::string(boost::json::parse(result.response->body()).at("error").at("code").as_string()); }

// Each test's own router, throttle and time, with limits loose enough not to interfere
// unless the test is about them.
struct Fixture {
  boost::asio::io_context io;
  dannan::test::SteppedTime time;
  std::shared_ptr<Router> router;

  explicit Fixture(RateLimits limits = {{1000, 1000}}) { router = std::make_shared<Router>(io.get_executor(), std::make_shared<Throttle>(time, limits)); }

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
  const auto result = call(f.io, f.router->middleware("/api/"), http::verb::get, "/health");
  EXPECT_TRUE(result.passed_on);
  EXPECT_FALSE(result.answered);
}

TEST(Router, AnOpenRouteAnswers) {
  Fixture f;
  f.router->add_open(http::verb::get, "/health", [](RouteContext context) {
    context.response->body() = "ok";
    context.done();
  });

  const auto result = call(f.io, f.router->middleware("/health"), http::verb::get, "/health");
  EXPECT_TRUE(result.answered);
  EXPECT_EQ(result.response->body(), "ok");
}

TEST(Router, PathParametersAreDecodedAndTheRemoteIsPassed) {
  Fixture f;
  f.ok_route(http::verb::get, "/api/v1/apps/{id}");

  const auto result = call(f.io, f.router->middleware("/api/"), http::verb::get, "/api/v1/apps/app%5F7f3k", "203.0.113.7");
  EXPECT_EQ(result.response->body(), "id=app_7f3k from 203.0.113.7");
}

TEST(Router, QueryIsParsedAndDoesNotAffectMatching) {
  Fixture f;
  f.router->add_open(http::verb::get, "/api/v1/things", [](RouteContext context) {
    context.response->body() = context.query["a"] + "|" + context.query["b"] + "|" + std::to_string(context.query.count("c"));
    context.done();
  });

  const auto result = call(f.io, f.router->middleware("/api/"), http::verb::get, "/api/v1/things?a=1+2&b=%41&c");
  EXPECT_EQ(result.response->body(), "1 2|A|1");
}

TEST(Router, UnknownPathIs404) {
  Fixture f;
  const auto result = call(f.io, f.router->middleware("/api/"), http::verb::get, "/api/v1/nothing");
  EXPECT_EQ(result.response->result(), http::status::not_found);
  EXPECT_EQ(error_code(result), "not_found");
}

TEST(Router, KnownPathWrongMethodIs405) {
  Fixture f;
  f.ok_route(http::verb::get, "/api/v1/apps");
  const auto result = call(f.io, f.router->middleware("/api/"), http::verb::delete_, "/api/v1/apps");
  EXPECT_EQ(result.response->result(), http::status::method_not_allowed);
}

TEST(Router, OpenRoutesAreLimitedByClientAddress) {
  Fixture f(RateLimits{{2, 1}});
  f.router->add_open(http::verb::get, "/health", [](RouteContext context) { context.done(); });
  const auto middleware = f.router->middleware("/health");

  EXPECT_EQ(call(f.io, middleware, http::verb::get, "/health").response->result(), http::status::ok);
  EXPECT_EQ(call(f.io, middleware, http::verb::get, "/health").response->result(), http::status::ok);

  const auto refused = call(f.io, middleware, http::verb::get, "/health");
  EXPECT_EQ(refused.response->result(), http::status::too_many_requests);
  EXPECT_EQ(refused.response->at(http::field::retry_after), "60");

  // Another client is not held up.
  EXPECT_EQ(call(f.io, middleware, http::verb::get, "/health", "198.51.100.4").response->result(), http::status::ok);

  f.time.advance(std::chrono::seconds(60));
  EXPECT_EQ(call(f.io, middleware, http::verb::get, "/health").response->result(), http::status::ok);
}

TEST(Router, UnknownPathsAreLimitedTooAgainstScanning) {
  Fixture f(RateLimits{{1, 1}});
  const auto middleware = f.router->middleware("/api/");

  EXPECT_EQ(call(f.io, middleware, http::verb::get, "/api/a").response->result(), http::status::not_found);
  EXPECT_EQ(call(f.io, middleware, http::verb::get, "/api/b").response->result(), http::status::too_many_requests);
}

TEST(Router, PercentDecode) {
  EXPECT_EQ(Router::percent_decode("a%40b.c"), "a@b.c");
  EXPECT_EQ(Router::percent_decode("a+b"), "a b");
  EXPECT_EQ(Router::percent_decode("100%"), "100%");
  EXPECT_EQ(Router::percent_decode("%zz"), "%zz");
}

namespace {

// Admits "Bearer good" as a caller holding "read".
class FixedResolver : public http::CallerResolver {
 public:
  http::Caller resolve(const http::HttpRequest& request) const override {
    const auto header = request.find(http::field::authorization);
    if (header == request.end() || header->value() != "Bearer good") return {};
    return http::Caller{http::Caller::Kind::user, "tester", {"read"}};
  }
};

struct Protected {
  boost::asio::io_context io;
  dannan::test::SteppedTime time;
  std::shared_ptr<Router> router;
  std::string seen;
  int ran = 0;

  explicit Protected(RateLimits limits = {{1000, 1000}, {1000, 1000}}, bool with_resolver = true, std::size_t most_in_flight = Router::kMostInFlight) {
    router = std::make_shared<Router>(io.get_executor(), std::make_shared<Throttle>(time, limits), with_resolver ? std::make_shared<FixedResolver>() : nullptr,
                                      most_in_flight);
    for (const auto* scope : {"read", "write"}) {
      router->add(http::verb::get, std::string("/api/") + scope, scope, [this](RouteContext context) {
        ++ran;
        seen = context.caller.id;
        context.response->result(http::status::ok);
        context.done();
      });
    }
    router->add(http::verb::get, "/api/throws", "read", [](RouteContext) { throw std::runtime_error("a handler that fails"); });
  }

  // Sent, and the io_context run until nothing is left.
  RouteCall get(const std::string& target, const std::string& authorization = "Bearer good") {
    return call(io, router->middleware("/api"), http::verb::get, target, "203.0.113.7", "", {{http::field::authorization, authorization}});
  }

  // Sent, and nothing run: what is answered here was answered before any handler ran.
  RouteCall send(const std::string& target) {
    RouteCall result;
    http::HttpRequest request{http::verb::get, target, 11};
    request.set(http::field::authorization, "Bearer good");
    router->middleware("/api")(request, "203.0.113.7", result.response, [&result](bool) { result.answered = true; });
    return result;
  }
};

}  // namespace

TEST(Router, AProtectedRouteWantsACredential) {
  Protected p;
  const auto result = p.get("/api/read", "Bearer bad");
  EXPECT_EQ(result.response->result(), http::status::unauthorized);
  EXPECT_EQ(error_code(result), "unauthorized");
  EXPECT_EQ(result.response->base()[http::field::www_authenticate], "Bearer realm=\"lugh\"");
  EXPECT_TRUE(p.seen.empty());
}

TEST(Router, AProtectedRouteWantsItsScope) {
  Protected p;
  EXPECT_EQ(p.get("/api/read").response->result(), http::status::ok);
  EXPECT_EQ(p.seen, "tester");

  const auto refused = p.get("/api/write");
  EXPECT_EQ(refused.response->result(), http::status::forbidden);
  EXPECT_EQ(error_code(refused), "forbidden");
}

TEST(Router, WithoutAResolverNobodyIsAdmitted) {
  Protected p({{1000, 1000}, {1000, 1000}}, false);
  EXPECT_EQ(p.get("/api/read").response->result(), http::status::unauthorized);
}

TEST(Router, CallersAreLimitedByCallerAndStrangersByAddress) {
  Protected p({{2, 2}, {3, 3}});
  for (int i = 0; i < 3; ++i) EXPECT_EQ(p.get("/api/read").response->result(), http::status::ok) << i;
  EXPECT_EQ(p.get("/api/read").response->result(), http::status::too_many_requests);

  for (int i = 0; i < 2; ++i) EXPECT_EQ(p.get("/api/read", "").response->result(), http::status::unauthorized) << i;
  EXPECT_EQ(p.get("/api/read", "").response->result(), http::status::too_many_requests);
}

TEST(Router, AHandlerRunsOnTheRoutersExecutorNotTheCallersThread) {
  Protected p;
  const auto pending = p.send("/api/read");
  // Spawned, not run: nothing is answered on the connection's thread.
  EXPECT_FALSE(pending.answered);
  EXPECT_EQ(p.ran, 0);
  p.io.run();
  EXPECT_EQ(p.ran, 1);
  EXPECT_EQ(p.seen, "tester");
}

TEST(Router, RefusalsAreAnsweredBeforeAnythingIsSpawned) {
  Protected p;
  http::HttpRequest request{http::verb::get, "/api/write", 11};
  request.set(http::field::authorization, "Bearer good");
  bool answered = false;
  p.router->middleware("/api")(request, "203.0.113.7", std::make_shared<http::HttpResponse>(), [&answered](bool) { answered = true; });
  EXPECT_TRUE(answered);
  EXPECT_EQ(p.io.run(), 0u);
  EXPECT_EQ(p.ran, 0);
}

TEST(Router, PastItsLimitTheRouterIsBusy) {
  Protected p({{1000, 1000}, {1000, 1000}}, true, 1);
  const auto first = p.send("/api/read");
  const auto second = p.send("/api/read");
  EXPECT_FALSE(first.answered);
  ASSERT_TRUE(second.answered);
  EXPECT_EQ(second.response->result(), http::status::service_unavailable);
  EXPECT_EQ(boost::json::parse(second.response->body()).at("error").at("code").as_string(), "busy");
  EXPECT_EQ(second.response->base()[http::field::retry_after], "1");

  // Once the first is done, there is room again.
  p.io.run();
  EXPECT_EQ(p.get("/api/read").response->result(), http::status::ok);
}

TEST(Router, AHandlerThatThrowsIsAnsweredOnce) {
  Protected p;
  int answers = 0;
  http::HttpRequest request{http::verb::get, "/api/throws", 11};
  request.set(http::field::authorization, "Bearer good");
  auto response = std::make_shared<http::HttpResponse>();
  p.router->middleware("/api")(request, "203.0.113.7", response, [&answers](bool) { ++answers; });
  p.io.run();
  EXPECT_EQ(answers, 1);
  EXPECT_EQ(response->result(), http::status::internal_server_error);
  EXPECT_EQ(boost::json::parse(response->body()).at("error").at("code").as_string(), "failed");
  EXPECT_EQ(response->body().find("a handler that fails"), std::string::npos);
}

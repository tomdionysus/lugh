//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What the API parses itself before a handler sees a request: the path against the route
// table, the query, percent-encoding, If-Match, and a body checked member by member. The
// JSON grammar is Boost's. Input: a target line, an If-Match line, then the body.

#include <boost/asio/io_context.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "api/api_support.h"
#include "http/router.h"
#include "system/clock.h"

namespace {

class StillClock : public lugh::system::Clock {
 public:
  std::chrono::system_clock::time_point wall_now() const override { return {}; }
  std::chrono::steady_clock::time_point steady_now() const override { return {}; }
};

class Everyone : public lugh::http::CallerResolver {
 public:
  lugh::http::Caller resolve(const lugh::http::HttpRequest&) const override { return lugh::http::Caller{lugh::http::Caller::Kind::user, "fuzz", {"s"}}; }
};

boost::asio::io_context io;

std::shared_ptr<lugh::http::Router> make_router() {
  using namespace lugh;
  auto router = std::make_shared<http::Router>(
      io.get_executor(), std::make_shared<http::Throttle>(std::make_shared<StillClock>(), http::RateLimits{{0, 0}, {0, 0}}), std::make_shared<Everyone>());
  const auto handler = [](http::RouteContext context) -> Task<void> {
    const auto precondition = api::if_match(context);
    std::optional<std::string> name;
    std::optional<bool> flag;
    std::uint64_t number = 0;
    if (precondition.ok) {
      if (const auto body = api::body_object(context, {"name", "flag"})) {
        api::string_member(context, *body, "name", name) && api::bool_member(context, *body, "flag", flag) &&
            api::number_query(context, "limit", 1, 1000, number);
      }
    }
    (void)context.parameter("id");
    context.done();
    co_return;
  };
  for (const auto* pattern : {"/api/v1/users", "/api/v1/users/{id}", "/api/v1/users/{id}/factors/{factor}", "/api/v1/groups/{id}/members/{user}"}) {
    for (const auto method : {http::verb::get, http::verb::post, http::verb::patch, http::verb::put, http::verb::delete_}) {
      router->add(method, pattern, "s", handler);
    }
  }
  return router;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh;
  static const auto router = make_router();
  static const auto middleware = router->middleware("/api");

  const std::string input(reinterpret_cast<const char*>(data), size);
  const auto first = input.find('\n');
  const auto second = first == std::string::npos ? std::string::npos : input.find('\n', first + 1);
  const auto target = input.substr(0, first);
  const auto match = first == std::string::npos ? std::string() : input.substr(first + 1, second == std::string::npos ? std::string::npos : second - first - 1);
  const auto body = second == std::string::npos ? std::string() : input.substr(second + 1);

  http::HttpRequest request;
  request.version(11);
  request.method(size % 2 ? http::verb::patch : http::verb::get);
  try {
    request.target(target);
    if (!match.empty()) request.set(http::field::if_match, match);
  } catch (const std::exception&) {
    // Beast refuses a field value with a control character; so does the server's parser.
    return 0;
  }
  request.body() = body;

  auto response = std::make_shared<http::HttpResponse>();
  bool answered = false;
  middleware(request, "192.0.2.1", response, [&answered](bool) { answered = true; });
  io.restart();
  io.run();
  if (!answered) __builtin_trap();
  return 0;
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/task.h"
#include "http/caller.h"
#include "http/http_types.h"
#include "http/rate_limiter.h"

namespace lugh::http {

// What a handler is given. The request is shared, not borrowed: handlers are async and may
// answer after the connection has moved on.
struct RouteContext {
  std::unordered_map<std::string, std::string> parameters;
  std::unordered_map<std::string, std::string> query;
  std::shared_ptr<const HttpRequest> request;

  // The caller, resolved by the router before the handler runs. On an open route it is
  // always Kind::none.
  Caller caller;

  // The client's address, as ClientAddress decided it.
  std::string remote;

  std::shared_ptr<HttpResponse> response;

  // Sends the response. Call once, on any thread; a second call does nothing.
  std::function<void()> done;

  // By value: callers read a parameter and move the context in the same call, and a
  // reference would dangle.
  std::string parameter(const std::string& name) const {
    const auto it = parameters.find(name);
    return it == parameters.end() ? std::string() : it->second;
  }

  const std::string& body() const { return request->body(); }
};

// Method, path and the scope that admits it, in one table: authorisation is part of
// declaring a route, not something a handler remembers to do. Every handler is a coroutine,
// spawned on the router's executor once the credential, the limits and the scope have been
// checked in memory; it awaits the store, the hashing pool or anything else without holding
// a thread, and answers by calling done(). At most `most_in_flight` run at once: past that
// a request is answered 503 at once, never queued.
class Router : public std::enable_shared_from_this<Router> {
 public:
  using Handler = std::function<Task<void>(RouteContext)>;

  static constexpr std::size_t kMostInFlight = 256;

  // Without a resolver every protected route answers 401.
  Router(Executor executor, std::shared_ptr<Throttle> throttle, std::shared_ptr<CallerResolver> resolver = nullptr, std::size_t most_in_flight = kMostInFlight);

  std::shared_ptr<Throttle> throttle() const { return _throttle; }

  // 429 with the wait in Retry-After (RFC 6585, RFC 9110 10.2.3) and in the message.
  static void write_too_many(const std::shared_ptr<HttpResponse>& response, std::chrono::seconds wait);

  // A route for a caller holding `scope`. Limited by caller once resolved, and by client
  // address while not.
  void add(verb method, const std::string& pattern, std::string scope, Handler handler);

  // A route that needs no credential: the health check, discovery, and the sign-in that
  // hands credentials out. Limited by client address.
  void add_open(verb method, const std::string& pattern, Handler handler);

  // The middleware for the chain. It answers everything under its prefix and passes the
  // rest along, so the dashboard and the API share a port.
  HttpMiddleware middleware(std::string prefix);

  // Path parameters arrive percent-encoded.
  static std::string percent_decode(const std::string& value);

 private:
  struct Route {
    verb method;
    std::vector<std::string> pattern;
    // Empty for an open route.
    std::string scope;
    bool open = false;
    Handler handler;
  };

  void _handle(const std::string& prefix, const HttpRequest& request, const std::string& remote, std::shared_ptr<HttpResponse> response,
               std::function<void(bool)> next);

  static std::string _source_key(const std::string& remote) { return "source:" + remote; }
  static std::vector<std::string> _split(const std::string& path);
  static bool _matches(const std::vector<std::string>& pattern, const std::vector<std::string>& segments, std::unordered_map<std::string, std::string>& out);
  static std::unordered_map<std::string, std::string> _parse_query(const std::string& query);

  std::shared_ptr<Throttle> _throttle;
  void _spawn(const Handler& handler, RouteContext context);

  Executor _executor;
  std::shared_ptr<CallerResolver> _resolver;
  std::size_t _most_in_flight;
  std::atomic<std::size_t> _in_flight{0};
  std::vector<Route> _routes;
};

}  // namespace lugh::http

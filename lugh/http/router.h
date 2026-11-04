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

#include "lugh/core/completion.h"
#include "lugh/http/caller.h"
#include "lugh/http/http_types.h"
#include "lugh/http/rate_limiter.h"

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

  // Where the handler is run and is answered by what it calls.
  Executor executor;

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
// declaring a route, not something a handler remembers to do. A handler is run on the
// router's executor once the credential, the limits and the scope have been checked in
// memory; it starts what it needs in Dannan's shape (core/completion.h), answered on
// context.executor, and answers the request by calling done(). A request is in flight from
// then until done(); at most `most_in_flight` are, and past that one is answered 503 at
// once, never queued. A handler that throws while starting is answered 500; what it starts
// answers through done(), and does not throw.
class Router : public std::enable_shared_from_this<Router> {
 public:
  using Handler = std::function<void(RouteContext)>;

  static constexpr std::size_t kMostInFlight = 256;

  // Without a resolver every protected route answers 401.
  Router(Executor executor, std::shared_ptr<Throttle> throttle, std::shared_ptr<CallerResolver> resolver = nullptr, std::size_t most_in_flight = kMostInFlight);

  std::shared_ptr<Throttle> throttle() const { return _throttle; }

  // 429 with the wait in Retry-After (RFC 6585, RFC 9110 10.2.3) and in the message.
  static void write_too_many(const std::shared_ptr<HttpResponse>& response, std::chrono::seconds wait);

  // A route for a caller holding `scope`. Limited by caller once resolved, and by client
  // address while not.
  void add(verb method, const std::string& pattern, std::string scope, Handler handler);

  // A route for any caller with a credential, whatever it holds: what the caller may know
  // about itself (/api/v1/me). Limited by caller.
  void add_authenticated(verb method, const std::string& pattern, Handler handler);

  // A route that needs no credential: the health check, discovery, and the sign-in that
  // hands credentials out. Limited by client address.
  void add_open(verb method, const std::string& pattern, Handler handler);

  // The middleware for the chain. It answers everything under its prefix and passes the
  // rest along, so the dashboard and the API share a port.
  HttpMiddleware middleware(std::string prefix);

 private:
  struct Route {
    verb method;
    std::vector<std::string> pattern;
    // Empty for an open route, and for one any caller may use.
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
  // The route's path parameters (strictly) and the query (as a form) percent-decoded into
  // the context, with Dannan's decoder; false, having written the 400, for a malformed escape.
  static bool _decode(RouteContext& context, const std::string& query);

  std::shared_ptr<Throttle> _throttle;
  void _dispatch(const Handler& handler, RouteContext context);

  Executor _executor;
  std::shared_ptr<CallerResolver> _resolver;
  std::size_t _most_in_flight;
  std::atomic<std::size_t> _in_flight{0};
  std::vector<Route> _routes;
};

}  // namespace lugh::http

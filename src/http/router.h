#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "http/http_types.h"
#include "http/rate_limiter.h"

namespace lugh::http {

// What a handler is given. The request is shared, not borrowed: handlers are async and may
// answer after the connection has moved on.
struct RouteContext {
  std::unordered_map<std::string, std::string> parameters;
  std::unordered_map<std::string, std::string> query;
  std::shared_ptr<const HttpRequest> request;

  // The client's address, as ClientAddress decided it.
  std::string remote;

  std::shared_ptr<HttpResponse> response;

  // Sends the response. Call exactly once, on any thread.
  std::function<void()> done;

  // By value: callers read a parameter and move the context in the same call, and a
  // reference would dangle.
  std::string parameter(const std::string& name) const {
    const auto it = parameters.find(name);
    return it == parameters.end() ? std::string() : it->second;
  }

  const std::string& body() const { return request->body(); }
};

// Method and path in one table. Routes that need a credential arrive with the session
// model, declaring who may call them here, so that authorisation is part of declaring a
// route and not something a handler remembers to do.
class Router : public std::enable_shared_from_this<Router> {
 public:
  using Handler = std::function<void(RouteContext)>;

  explicit Router(std::shared_ptr<Throttle> throttle);

  std::shared_ptr<Throttle> throttle() const { return _throttle; }

  // 429 with the wait in Retry-After (RFC 6585, RFC 9110 10.2.3) and in the message.
  static void write_too_many(const std::shared_ptr<HttpResponse>& response, std::chrono::seconds wait);

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
    Handler handler;
  };

  void _handle(const std::string& prefix, const HttpRequest& request, const std::string& remote, std::shared_ptr<HttpResponse> response,
               std::function<void(bool)> next);

  static std::string _source_key(const std::string& remote) { return "source:" + remote; }
  static std::vector<std::string> _split(const std::string& path);
  static bool _matches(const std::vector<std::string>& pattern, const std::vector<std::string>& segments, std::unordered_map<std::string, std::string>& out);
  static std::unordered_map<std::string, std::string> _parse_query(const std::string& query);

  std::shared_ptr<Throttle> _throttle;
  std::vector<Route> _routes;
};

}  // namespace lugh::http

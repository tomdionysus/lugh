//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "http/router.h"

#include <boost/asio/co_spawn.hpp>
#include <cctype>
#include <utility>

#include "http/api_json.h"

namespace lugh::http {

Router::Router(Executor executor, std::shared_ptr<Throttle> throttle, std::shared_ptr<CallerResolver> resolver, std::size_t most_in_flight)
    : _throttle(std::move(throttle)), _executor(std::move(executor)), _resolver(std::move(resolver)), _most_in_flight(most_in_flight) {}

void Router::write_too_many(const std::shared_ptr<HttpResponse>& response, std::chrono::seconds wait) {
  write_error(response, status::too_many_requests, "rate_limited",
              "too many requests; try again in " + std::to_string(wait.count()) + (wait.count() == 1 ? " second" : " seconds"));
  response->set(field::retry_after, std::to_string(wait.count()));
}

void Router::add(verb method, const std::string& pattern, std::string scope, Handler handler) {
  _routes.push_back(Route{method, _split(pattern), std::move(scope), false, std::move(handler)});
}

void Router::add_open(verb method, const std::string& pattern, Handler handler) {
  _routes.push_back(Route{method, _split(pattern), {}, true, std::move(handler)});
}

HttpMiddleware Router::middleware(std::string prefix) {
  return [self = shared_from_this(), prefix = std::move(prefix)](const HttpRequest& request, const std::string& remote, std::shared_ptr<HttpResponse> response,
                                                                 std::function<void(bool)> next) {
    self->_handle(prefix, request, remote, std::move(response), std::move(next));
  };
}

void Router::_handle(const std::string& prefix, const HttpRequest& request, const std::string& remote, std::shared_ptr<HttpResponse> response,
                     std::function<void(bool)> next) {
  const std::string target(request.target());
  if (target.rfind(prefix, 0) != 0) return next(true);

  const auto question = target.find('?');
  const auto path = question == std::string::npos ? target : target.substr(0, question);
  const auto segments = _split(path);

  // No route matches the path: 404. A route matches with another method: 405.
  bool path_matched = false;

  for (const auto& route : _routes) {
    std::unordered_map<std::string, std::string> parameters;
    if (!_matches(route.pattern, segments, parameters)) continue;

    path_matched = true;
    if (route.method != request.method()) continue;

    RouteContext context;
    context.parameters = std::move(parameters);
    context.query = _parse_query(question == std::string::npos ? std::string() : target.substr(question + 1));
    context.request = std::make_shared<const HttpRequest>(request);
    context.remote = remote;
    context.response = response;
    // Once only: a handler that answers and then fails is not answered twice.
    context.done = [next, answered = std::make_shared<std::atomic<bool>>(false)]() {
      if (!answered->exchange(true)) next(false);
    };

    if (!route.open) {
      context.caller = _resolver ? _resolver->resolve(request) : Caller{};

      // An unresolved credential is limited as an open route is, by client address.
      if (!context.caller.authenticated()) {
        if (const auto wait = _throttle->take(_source_key(remote), _throttle->limits().open)) {
          write_too_many(response, *wait);
          return next(false);
        }
        response->set(field::www_authenticate, "Bearer realm=\"lugh\"");
        write_error(response, status::unauthorized, "unauthorized", "a credential is needed");
        return next(false);
      }

      if (const auto wait = _throttle->take("caller:" + context.caller.id, _throttle->limits().caller)) {
        write_too_many(response, *wait);
        return next(false);
      }

      // A real credential without the scope is a 403, not a 401. Scope names are documented
      // vocabulary and safe to say.
      if (!context.caller.has_scope(route.scope)) {
        write_error(response, status::forbidden, "forbidden", "this credential does not hold the scope " + route.scope);
        return next(false);
      }

      return _spawn(route.handler, std::move(context));
    }

    if (const auto wait = _throttle->take(_source_key(remote), _throttle->limits().open)) {
      write_too_many(response, *wait);
      return next(false);
    }
    return _spawn(route.handler, std::move(context));
  }

  // Unknown endpoints are limited too, against scanning.
  if (const auto wait = _throttle->take(_source_key(remote), _throttle->limits().open)) {
    write_too_many(response, *wait);
    return next(false);
  }

  if (path_matched) {
    write_error(response, status::method_not_allowed, "method_not_allowed", "that path does not take this method");
    return next(false);
  }

  write_error(response, status::not_found, "not_found", "no such endpoint");
  next(false);
}

void Router::_spawn(const Handler& handler, RouteContext context) {
  auto held = _in_flight.load();
  do {
    if (held >= _most_in_flight) {
      write_error(context.response, status::service_unavailable, "busy", "the server is busy; try again in a second");
      context.response->set(field::retry_after, "1");
      return context.done();
    }
  } while (!_in_flight.compare_exchange_weak(held, held + 1));

  auto response = context.response;
  auto done = context.done;
  boost::asio::co_spawn(_executor, handler(std::move(context)), [self = shared_from_this(), response, done](std::exception_ptr failure) {
    --self->_in_flight;
    if (!failure) return;
    // A handler that threw has said nothing useful; what it was is not for the caller.
    write_error(response, status::internal_server_error, "failed", "the request could not be completed");
    done();
  });
}

std::vector<std::string> Router::_split(const std::string& path) {
  std::vector<std::string> segments;

  std::size_t start = 0;
  while (start <= path.size()) {
    const auto slash = path.find('/', start);
    auto segment = slash == std::string::npos ? path.substr(start) : path.substr(start, slash - start);

    if (!segment.empty()) segments.push_back(std::move(segment));
    if (slash == std::string::npos) break;

    start = slash + 1;
  }

  return segments;
}

bool Router::_matches(const std::vector<std::string>& pattern, const std::vector<std::string>& segments, std::unordered_map<std::string, std::string>& out) {
  if (pattern.size() != segments.size()) return false;

  for (std::size_t i = 0; i < pattern.size(); ++i) {
    const auto& expected = pattern[i];

    if (expected.size() > 2 && expected.front() == '{' && expected.back() == '}') {
      out[expected.substr(1, expected.size() - 2)] = percent_decode(segments[i]);
      continue;
    }

    if (expected != segments[i]) return false;
  }

  return true;
}

std::unordered_map<std::string, std::string> Router::_parse_query(const std::string& query) {
  std::unordered_map<std::string, std::string> parsed;

  std::size_t start = 0;
  while (start < query.size()) {
    auto amp = query.find('&', start);
    if (amp == std::string::npos) amp = query.size();

    const auto part = query.substr(start, amp - start);
    const auto equals = part.find('=');

    if (equals == std::string::npos) {
      if (!part.empty()) parsed[percent_decode(part)] = std::string();
    } else {
      parsed[percent_decode(part.substr(0, equals))] = percent_decode(part.substr(equals + 1));
    }

    start = amp + 1;
  }

  return parsed;
}

std::string Router::percent_decode(const std::string& value) {
  std::string out;
  out.reserve(value.size());

  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '+') {
      out.push_back(' ');
      continue;
    }

    if (value[i] != '%' || i + 2 >= value.size() || !std::isxdigit(static_cast<unsigned char>(value[i + 1])) ||
        !std::isxdigit(static_cast<unsigned char>(value[i + 2]))) {
      out.push_back(value[i]);
      continue;
    }

    out.push_back(static_cast<char>(std::stoi(value.substr(i + 1, 2), nullptr, 16)));
    i += 2;
  }

  return out;
}

}  // namespace lugh::http

#pragma once

#include <memory>
#include <string>

#include "http/http_types.h"

// One request through one middleware, synchronously: what it answered, and whether it
// passed the request on instead.
struct RouteCall {
  std::shared_ptr<lugh::http::HttpResponse> response = std::make_shared<lugh::http::HttpResponse>();
  bool passed_on = false;
  bool answered = false;
};

inline RouteCall call(const lugh::http::HttpMiddleware& middleware, lugh::http::verb method, const std::string& target,
                      const std::string& remote = "203.0.113.7", const std::string& body = "") {
  lugh::http::HttpRequest request{method, target, 11};
  request.body() = body;
  request.prepare_payload();

  RouteCall result;
  middleware(request, remote, result.response, [&result](bool more) {
    if (more)
      result.passed_on = true;
    else
      result.answered = true;
  });
  return result;
}

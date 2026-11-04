//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/io_context.hpp>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lugh/http/http_types.h"

// One request through one middleware: what it answered, and whether it passed the request
// on instead. The router runs its handlers as coroutines on `io`, which is run here until
// there is nothing left to do.
struct RouteCall {
  std::shared_ptr<lugh::http::HttpResponse> response = std::make_shared<lugh::http::HttpResponse>();
  bool passed_on = false;
  bool answered = false;
};

inline RouteCall call(boost::asio::io_context& io, const lugh::http::HttpMiddleware& middleware, lugh::http::verb method, const std::string& target,
                      const std::string& remote = "203.0.113.7", const std::string& body = "",
                      const std::vector<std::pair<lugh::http::field, std::string>>& headers = {}) {
  lugh::http::HttpRequest request{method, target, 11};
  for (const auto& [name, value] : headers) request.set(name, value);
  request.body() = body;
  request.prepare_payload();

  RouteCall result;
  middleware(request, remote, result.response, [&result](bool more) {
    if (more)
      result.passed_on = true;
    else
      result.answered = true;
  });
  io.restart();
  io.run();
  return result;
}

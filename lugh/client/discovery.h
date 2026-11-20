//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <string>
#include <variant>

#include "lugh/client/https.h"

// What the key source and discover() both read from an issuer: its discovery document
// (OpenID Connect Discovery 1.0, section 4), asked the same way and read the same way.
namespace lugh::client {

inline HttpsRequest discovery_request(const std::string& issuer) {
  HttpsRequest request;
  request.url = issuer + "/.well-known/openid-configuration";
  request.headers = {{"Accept", "application/json"}};
  return request;
}

// The body of a 200 answer as a JSON object, or why not.
inline std::variant<boost::json::object, std::string> json_answer(const Outcome<HttpsResponse>& answered, const std::string& what) {
  if (!answered.ok()) return what + ": " + answered.message;
  if (answered.value.status != 200) return what + " answered " + std::to_string(answered.value.status);
  boost::system::error_code ec;
  auto parsed = boost::json::parse(answered.value.body, ec);
  if (ec || !parsed.is_object()) return what + " is not a JSON object";
  return std::move(parsed.as_object());
}

}  // namespace lugh::client

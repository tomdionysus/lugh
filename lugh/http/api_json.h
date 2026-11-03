//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "lugh/http/http_types.h"

namespace lugh::http {

// The one error shape for the whole API:
//
//   { "error": { "code": "not_found", "message": "no such endpoint" } }
//
// Clients branch on the code, which never changes; the message is for a person, and never
// carries a secret or anything a caller typed.
inline void write_error(const std::shared_ptr<HttpResponse>& response, status status, std::string code, std::string message) {
  boost::json::object error;
  error["code"] = std::move(code);
  error["message"] = std::move(message);

  boost::json::object body;
  body["error"] = std::move(error);

  response->result(status);
  response->set(field::content_type, "application/json");
  response->set(field::cache_control, "no-store");
  response->body() = boost::json::serialize(body);
}

inline void write_json(const std::shared_ptr<HttpResponse>& response, status status, const boost::json::value& value) {
  response->result(status);
  response->set(field::content_type, "application/json");
  response->set(field::cache_control, "no-store");
  response->body() = boost::json::serialize(value);
}

// 204 carries no body and no content type.
inline void write_no_content(const std::shared_ptr<HttpResponse>& response) {
  response->result(status::no_content);
  response->body().clear();
}

// nullopt for a body that is not a JSON object, which the caller answers with a 400. An
// empty body is an empty object.
inline std::optional<boost::json::object> parse_object(const std::string& body) {
  if (body.empty()) return boost::json::object{};

  boost::system::error_code ec;
  const auto parsed = boost::json::parse(body, ec);
  if (ec || !parsed.is_object()) return std::nullopt;

  return parsed.as_object();
}

// nullopt when the field is absent or not a string: on a PATCH, "not given" and "given as
// empty" differ.
inline std::optional<std::string> string_field(const boost::json::object& object, const std::string& name) {
  const auto it = object.find(name);
  if (it == object.end() || !it->value().is_string()) return std::nullopt;

  return std::string(it->value().as_string());
}

}  // namespace lugh::http

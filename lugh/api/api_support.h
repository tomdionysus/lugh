//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <ctime>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

#include "lugh/audit/audit_log.h"
#include "lugh/core/outcome.h"
#include "lugh/http/api_json.h"
#include "lugh/http/router.h"

namespace lugh::api {

// What every /api/v1 route shares: the actor for the audit log, the status for a fault,
// ETags, and checking a body before anything reads it.

inline audit::Actor actor_of(const http::RouteContext& context) { return audit::Actor{context.caller.id, context.remote}; }

// One status per fault, and the error code a client branches on.
inline void write_fault(const std::shared_ptr<http::HttpResponse>& response, Fault fault, const std::string& message) {
  switch (fault) {
    case Fault::not_found:
      return http::write_error(response, http::status::not_found, "not_found", message);
    case Fault::conflict:
      return http::write_error(response, http::status::precondition_failed, "changed", message);
    case Fault::duplicate:
      return http::write_error(response, http::status::conflict, "duplicate", message);
    case Fault::invalid:
      return http::write_error(response, http::status::bad_request, "invalid", message);
    case Fault::refused:
      return http::write_error(response, http::status::conflict, "refused", message);
    case Fault::none:
    case Fault::failed:
      break;
  }
  // The store or the randomness: what failed is in the log, not the response.
  http::write_error(response, http::status::internal_server_error, "failed", "the change could not be made; nothing was changed");
}

template <typename T>
void write_fault(const std::shared_ptr<http::HttpResponse>& response, const Outcome<T>& outcome) {
  write_fault(response, outcome.fault, outcome.message);
}

// A strong ETag (RFC 9110, section 8.8.3) of the record's version.
inline std::string etag(std::uint64_t version) { return "\"" + std::to_string(version) + "\""; }

// The version a write must find, from If-Match. Required on every write to something that
// exists, so that no client overwrites a change it has not seen: 428 without one (RFC
// 6585), 412 for one that is not ours or not current. "*" asks for no check.
struct Precondition {
  bool ok = false;
  std::optional<std::uint64_t> expected;
};

inline Precondition if_match(const http::RouteContext& context) {
  const auto header = context.request->find(http::field::if_match);
  if (header == context.request->end()) {
    http::write_error(context.response, http::status::precondition_required, "if_match_required",
                      "send If-Match with the ETag you last read, or * to overwrite whatever is there");
    return {};
  }
  const std::string value(header->value());
  if (value == "*") return Precondition{true, std::nullopt};
  if (value.size() >= 3 && value.front() == '"' && value.back() == '"' && value.size() <= 22) {
    std::uint64_t version = 0;
    bool digits = true;
    for (std::size_t i = 1; i + 1 < value.size(); ++i) {
      if (value[i] < '0' || value[i] > '9') digits = false;
      version = version * 10 + static_cast<std::uint64_t>(value[i] - '0');
    }
    if (digits) return Precondition{true, version};
  }
  http::write_error(context.response, http::status::precondition_failed, "changed", "If-Match does not name a version of this resource");
  return {};
}

// RFC 3339, UTC, to the second.
inline std::string timestamp(std::uint64_t seconds) {
  const auto time = static_cast<std::time_t>(seconds);
  std::tm utc{};
  gmtime_r(&time, &utc);
  char buffer[32];
  std::strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &utc);
  return buffer;
}

// The body as an object whose every member is one the route takes. A member the route
// does not know is refused, not ignored: a misspelt field would otherwise be a silent no-op.
inline std::optional<boost::json::object> body_object(const http::RouteContext& context, std::initializer_list<std::string_view> allowed) {
  auto parsed = http::parse_object(context.body());
  if (!parsed) {
    http::write_error(context.response, http::status::bad_request, "invalid", "the body must be a JSON object");
    return std::nullopt;
  }
  for (const auto& member : *parsed) {
    bool known = false;
    for (const auto name : allowed) known = known || member.key() == name;
    if (!known) {
      http::write_error(context.response, http::status::bad_request, "invalid", "unknown field " + std::string(member.key()));
      return std::nullopt;
    }
  }
  return parsed;
}

// A member that must be a string when present. Answers false, having written the 400, when
// it is something else.
inline bool string_member(const http::RouteContext& context, const boost::json::object& object, std::string_view name, std::optional<std::string>& out) {
  const auto it = object.find(name);
  if (it == object.end()) return true;
  if (!it->value().is_string()) {
    http::write_error(context.response, http::status::bad_request, "invalid", std::string(name) + " must be a string");
    return false;
  }
  out = std::string(it->value().as_string());
  return true;
}

inline bool bool_member(const http::RouteContext& context, const boost::json::object& object, std::string_view name, std::optional<bool>& out) {
  const auto it = object.find(name);
  if (it == object.end()) return true;
  if (!it->value().is_bool()) {
    http::write_error(context.response, http::status::bad_request, "invalid", std::string(name) + " must be true or false");
    return false;
  }
  out = it->value().as_bool();
  return true;
}

// A query parameter that must be a whole number within bounds when present.
inline bool number_query(const http::RouteContext& context, const std::string& name, std::uint64_t least, std::uint64_t most, std::uint64_t& out) {
  const auto it = context.query.find(name);
  if (it == context.query.end()) return true;
  const auto& text = it->second;
  bool digits = !text.empty() && text.size() <= 19;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') digits = false;
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (!digits || value < least || value > most) {
    http::write_error(context.response, http::status::bad_request, "invalid",
                      name + " is a whole number from " + std::to_string(least) + " to " + std::to_string(most));
    return false;
  }
  out = value;
  return true;
}

}  // namespace lugh::api

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Reading a JWT's claims as the token checks need them: a member of the wrong type is as good as
// absent.
namespace lugh::client {

// A NumericDate (RFC 7519 section 2): a non-negative number of seconds, fractions dropped.
inline std::optional<std::uint64_t> seconds_claim(const boost::json::object& claims, std::string_view name) {
  const auto found = claims.if_contains(name);
  if (!found || !found->is_number()) return std::nullopt;
  const auto value = found->to_number<double>();
  if (value < 0) return std::nullopt;
  return static_cast<std::uint64_t>(value);
}

inline std::optional<std::string> string_claim(const boost::json::object& claims, std::string_view name) {
  const auto found = claims.if_contains(name);
  if (!found || !found->is_string()) return std::nullopt;
  return std::string(found->as_string());
}

// aud as a list (RFC 7519 section 4.1.3): one string, or the strings of an array.
inline std::vector<std::string> audiences_claim(const boost::json::object& claims) {
  std::vector<std::string> audiences;
  if (const auto aud = claims.if_contains("aud"); aud && aud->is_array()) {
    for (const auto& one : aud->as_array()) {
      if (one.is_string()) audiences.emplace_back(one.as_string());
    }
  } else if (aud && aud->is_string()) {
    audiences.emplace_back(aud->as_string());
  }
  return audiences;
}

}  // namespace lugh::client

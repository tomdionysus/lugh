//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/forms.h"

#include <stdexcept>

#include "dannan/encoding/percent.h"

namespace lugh::http {

std::optional<std::map<std::string, std::string>> parse_form(std::string_view body) {
  if (body.size() > kMostFormBytes) return std::nullopt;
  std::map<std::string, std::string> out;
  std::size_t start = 0;
  try {
    while (start < body.size()) {
      const auto end = std::min(body.find('&', start), body.size());
      const auto part = body.substr(start, end - start);
      start = end + 1;
      if (part.empty()) continue;
      const auto equals = part.find('=');
      auto name = dannan::encoding::percent_decode(part.substr(0, equals), dannan::encoding::Decoding::form);
      auto value =
          equals == std::string_view::npos ? std::string() : dannan::encoding::percent_decode(part.substr(equals + 1), dannan::encoding::Decoding::form);
      if (name.empty() || out.count(name)) return std::nullopt;
      out.emplace(std::move(name), std::move(value));
    }
  } catch (const std::invalid_argument&) {
    return std::nullopt;
  }
  return out;
}

std::optional<std::string> cookie(const HttpRequest& request, std::string_view name) {
  std::optional<std::string> found;
  for (const auto& field : request.base()) {
    if (field.name() != http::field::cookie) continue;
    const auto header = std::string_view(field.value());
    std::size_t start = 0;
    while (start < header.size()) {
      const auto end = std::min(header.find(';', start), header.size());
      auto pair = header.substr(start, end - start);
      start = end + 1;
      while (!pair.empty() && pair.front() == ' ') pair.remove_prefix(1);
      const auto equals = pair.find('=');
      if (equals == std::string_view::npos || pair.substr(0, equals) != name) continue;
      if (found) return std::nullopt;
      found = std::string(pair.substr(equals + 1));
    }
  }
  return found;
}

std::string host_cookie(std::string_view name, std::string_view value, long max_age) {
  return std::string(name) + "=" + std::string(value) + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(max_age);
}

}  // namespace lugh::http

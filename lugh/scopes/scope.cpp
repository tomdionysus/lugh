//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/scopes/scope.h"

#include <algorithm>

namespace lugh::scopes {

std::vector<std::string> lugh_scopes() {
  return {kDirectoryRead, kDirectoryWrite, kCredentialsWrite, kPoliciesWrite, kAuditRead, kAppsWrite, kKeysWrite, kSessionsWrite};
}

std::vector<std::string> oidc_scopes() { return {"openid", "profile", "email", "groups", "offline_access"}; }

std::optional<std::string_view> prefix_of(std::string_view scope) {
  const auto colon = scope.find(':');
  if (colon == std::string_view::npos) return std::nullopt;
  return scope.substr(0, colon);
}

bool valid_prefix(std::string_view prefix) {
  if (prefix.empty() || prefix.size() > 32 || prefix.front() < 'a' || prefix.front() > 'z') return false;
  return std::all_of(prefix.begin(), prefix.end(), [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

Outcome<Kind> grantable(std::string_view scope) {
  using Answer = Outcome<Kind>;
  if (!well_formed(scope)) return Answer::failure(Fault::invalid, "a scope is printable ASCII without spaces, quotes or backslashes, 1 to 1024 bytes");
  const auto text = std::string(scope);
  const auto prefix = prefix_of(scope);
  if (!prefix) {
    const auto oidc = oidc_scopes();
    if (std::find(oidc.begin(), oidc.end(), text) != oidc.end()) return Answer::success(Kind::oidc);
    return Answer::failure(Fault::invalid, "the scope " + text + " is neither an OIDC scope nor <prefix>:<name>");
  }
  if (*prefix == kLughPrefix) {
    const auto own = lugh_scopes();
    if (std::find(own.begin(), own.end(), text) != own.end()) return Answer::success(Kind::lugh);
    return Answer::failure(Fault::invalid, "Lugh has no scope " + text);
  }
  if (*prefix == kTopicPrefix) {
    if (!decode_topic(scope)) return Answer::failure(Fault::invalid, "the scope " + text + " is not a topic scope (lir:pub|sub|retain:<filter>)");
    return Answer::success(Kind::topic);
  }
  if (!valid_prefix(*prefix) || scope.size() == prefix->size() + 1)
    return Answer::failure(Fault::invalid, "an application's scope is <prefix>:<name>, the prefix lower-case letters, digits and '-'");
  return Answer::success(Kind::application);
}

std::optional<std::vector<std::string>> split(std::string_view text) {
  std::vector<std::string> out;
  std::size_t at = 0;
  while (at < text.size()) {
    if (text[at] == ' ') {
      ++at;
      continue;
    }
    const auto end = std::min(text.find(' ', at), text.size());
    const auto word = text.substr(at, end - at);
    if (!well_formed(word)) return std::nullopt;
    out.emplace_back(word);
    at = end;
  }
  return out;
}

std::vector<std::string> united(std::vector<std::string> scopes) {
  std::sort(scopes.begin(), scopes.end());
  scopes.erase(std::unique(scopes.begin(), scopes.end()), scopes.end());
  return scopes;
}

std::string join(std::vector<std::string> scopes) {
  std::string out;
  for (const auto& scope : united(std::move(scopes))) {
    if (!out.empty()) out.push_back(' ');
    out += scope;
  }
  return out;
}

}  // namespace lugh::scopes

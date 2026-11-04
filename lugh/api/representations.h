//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <string>
#include <string_view>

#include "dannan/identity/crypto.h"
#include "lugh/api/api_support.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/factors.h"
#include "lugh/core/encoding.h"
#include "lugh/directory/records.h"

namespace lugh::api {

// The JSON for each kind of thing, the same wherever it appears. Never a secret, a hash,
// or a store key that is not the resource's own ID.

inline boost::json::object user_json(const directory::User& user) {
  boost::json::object out;
  out["id"] = user.id;
  out["kind"] = user.kind == directory::Kind::person ? "person" : "service";
  out["name"] = user.name;
  out["email"] = user.email;
  out["display_name"] = user.display_name;
  out["given_name"] = user.given_name;
  out["family_name"] = user.family_name;
  if (user.posix_number) out["posix_number"] = *user.posix_number;
  out["enrolled"] = user.enrolled;
  out["disabled"] = user.disabled;
  out["created_at"] = timestamp(user.created);
  out["updated_at"] = timestamp(user.updated);
  return out;
}

inline boost::json::object group_json(const directory::Group& group) {
  boost::json::object out;
  out["id"] = group.id;
  out["name"] = group.name;
  out["description"] = group.description;
  if (group.posix_number) out["posix_number"] = *group.posix_number;
  out["created_at"] = timestamp(group.created);
  out["updated_at"] = timestamp(group.updated);
  return out;
}

// A factor's ID in a URL: its store key without the user in front, and with no '/'.
// "<user>/totp/<instance>" is "totp-<instance>".
inline std::string factor_id(std::string_view key) {
  const auto first = key.find('/');
  if (first == std::string_view::npos) return std::string(key);
  std::string out(key.substr(first + 1));
  const auto second = out.find('/');
  if (second != std::string::npos) out[second] = '-';
  return out;
}

// And back, for this user; empty for anything that is not one.
inline std::string factor_key(std::string_view user_id, std::string_view id) {
  const auto dash = id.find('-');
  if (dash == std::string_view::npos) return {};
  const auto kind = id.substr(0, dash);
  const auto instance = id.substr(dash + 1);
  if ((kind != "totp" && kind != "recovery") || instance.empty() || instance.find('/') != std::string_view::npos) return {};
  return std::string(user_id) + "/" + std::string(kind) + "/" + std::string(instance);
}

inline boost::json::object factor_json(const authn::FactorInfo& factor) {
  boost::json::object out;
  out["id"] = factor_id(factor.id);
  out["kind"] = factor.kind == authn::FactorKind::totp ? "totp" : "recovery";
  out["confirmed"] = factor.confirmed;
  out["created_at"] = timestamp(factor.created);
  if (factor.kind == authn::FactorKind::recovery) out["remaining"] = factor.remaining;
  return out;
}

inline boost::json::object entry_json(const audit::Entry& entry) {
  boost::json::object out;
  out["sequence"] = entry.sequence;
  out["time"] = timestamp(entry.time);
  out["action"] = entry.event.action;
  out["actor"] = entry.event.actor;
  out["subject"] = entry.event.subject;
  out["source"] = entry.event.source;
  out["detail"] = entry.event.detail;
  out["hash"] = dannan::identity::hex(entry.hash);
  out["previous"] = dannan::identity::hex(entry.previous);
  return out;
}

}  // namespace lugh::api

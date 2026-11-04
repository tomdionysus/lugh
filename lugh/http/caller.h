//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <algorithm>
#include <string>
#include <vector>

#include "lugh/http/http_types.h"

namespace lugh::http {

// Who is calling, and what they may do, resolved from a request before any protected route
// runs. After blackraven-admin's, with scopes in place of roles: a session or an OAuth
// token carries scopes (P6).
struct Caller {
  enum class Kind {
    // Nothing presented, or nothing that resolved: 401.
    none,
    // A signed-in person, or a client acting for one.
    user,
    // A client acting for itself, with client credentials: its id is its client_id.
    service,
  };

  Kind kind = Kind::none;
  // What the audit log records as the actor: a user ID, or a client ID.
  std::string id;
  std::vector<std::string> scopes;

  bool authenticated() const { return kind != Kind::none; }
  bool has_scope(const std::string& scope) const { return std::find(scopes.begin(), scopes.end(), scope) != scopes.end(); }
};

// What the router asks of a request before a protected route runs. Synchronous: every
// credential Lugh accepts is checked in memory, with no round trip.
class CallerResolver {
 public:
  virtual ~CallerResolver() = default;

  // Caller::Kind::none for a request with no credential, or one that does not resolve.
  virtual Caller resolve(const HttpRequest& request) const = 0;
};

}  // namespace lugh::http

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string_view>

#include "lugh/http/caller.h"
#include "lugh/session/sessions.h"

namespace lugh::session {

// The API's caller: an OAuth access token in `Authorization` (Bearer, or DPoP with its proof)
// whose audiences include `lugh` (oauth::api_caller(); a person's or a client's), or else a
// Lugh session:
// the `__Host-lugh_session` cookie, and, on any request that may change something (anything
// but GET and HEAD), the session's CSRF token in `X-CSRF-Token`. A token that does not verify,
// a session that does not resolve, or a change without the token, is no caller (401). The
// caller holds the token's scopes, or the session's as last read.
class SessionCallers : public http::CallerResolver {
 public:
  static constexpr const char* kCsrfHeader = "X-CSRF-Token";

  // The caller an Authorization header makes, checked from memory, or nothing:
  // oauth::api_caller().
  using BearerCheck = std::function<std::optional<http::Caller>(const http::HttpRequest& request)>;

  explicit SessionCallers(std::shared_ptr<Sessions> sessions, BearerCheck bearer = nullptr);

  http::Caller resolve(const http::HttpRequest& request) const override;

 private:
  std::shared_ptr<Sessions> _sessions;
  BearerCheck _bearer;
};

}  // namespace lugh::session

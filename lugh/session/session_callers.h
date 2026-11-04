//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/http/caller.h"
#include "lugh/session/sessions.h"

namespace lugh::session {

// The API's caller from a Lugh session: the `__Host-lugh_session` cookie, and, on any request
// that may change something (anything but GET and HEAD), the session's CSRF token in
// `X-CSRF-Token`. A session that does not resolve, or a change without the token, is no
// caller (401). The caller holds the session's scopes as last read. OAuth tokens join this
// with the token endpoint (O7).
class SessionCallers : public http::CallerResolver {
 public:
  static constexpr const char* kCsrfHeader = "X-CSRF-Token";

  explicit SessionCallers(std::shared_ptr<Sessions> sessions);

  http::Caller resolve(const http::HttpRequest& request) const override;

 private:
  std::shared_ptr<Sessions> _sessions;
};

}  // namespace lugh::session

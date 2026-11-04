//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/session/session_callers.h"

#include "lugh/http/forms.h"

namespace lugh::session {

SessionCallers::SessionCallers(std::shared_ptr<Sessions> sessions, BearerCheck bearer) : _sessions(std::move(sessions)), _bearer(std::move(bearer)) {}

http::Caller SessionCallers::resolve(const http::HttpRequest& request) const {
  // A bearer token is the caller when there is one: a request with Authorization is never also
  // taken from a cookie, so presenting a bad token does not fall back to a session.
  if (const auto authorization = request.find(http::field::authorization); authorization != request.end()) {
    if (!_bearer) return {};
    return _bearer(request).value_or(http::Caller{});
  }
  const auto handle = http::cookie(request, Sessions::kCookie);
  if (!handle) return {};
  const auto session = _sessions->find(*handle);
  if (!session) return {};

  // A request that only reads cannot be forged to any effect: a cross-site page cannot read
  // the answer. Anything else must prove it came from a page that could read the token.
  const auto method = request.method();
  if (method != http::verb::get && method != http::verb::head) {
    const auto token = request.find(kCsrfHeader);
    if (token == request.end() || !Sessions::csrf_ok(*session, std::string_view(token->value()))) return {};
  }
  return http::Caller{http::Caller::Kind::user, session->user_id, session->scopes};
}

}  // namespace lugh::session

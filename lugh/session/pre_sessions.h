//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/authn/authenticator.h"
#include "lugh/core/secure_bytes.h"

namespace lugh::session {

// A sign-in part way through, between the pages (TODO/2026-11-04-oauth.md, "The Lugh
// session"): what the authenticator handed back, held on the server under the cookie
// `__Host-lugh_signin`. Node-local and in memory: a sign-in that started on one node finishes
// there, and one that meets a restart starts again at the password. It lives as long as the
// authenticator allows a sign-in to take.
struct PreSession {
  authn::SignIn sign_in;
  // At enrolment, the TOTP factor being confirmed, and its secret and otpauth URI, so a
  // wrong code can be tried again against the same secret. In secure memory, and gone when
  // the sign-in is.
  std::string factor_id;
  SecureBuffer totp_secret;
  SecureBuffer totp_uri;
};

// The sign-ins in progress, and the cookie that names one. The cookie is set by the first page
// and is what every form's CSRF token is made from, with a key of this process's own, so a
// form posted from another site, which cannot read the cookie, carries no valid token. Nothing
// is held for a visitor until a password has been accepted, so an anonymous visitor costs
// nothing; past `most`, the oldest sign-in is dropped. Safe from any number of threads.
class PreSessions {
 public:
  static constexpr const char* kCookie = "__Host-lugh_signin";
  static constexpr std::size_t kHandleBytes = 32;

  PreSessions(const dannan::contract::TimeSource& time, std::chrono::seconds lifetime, std::size_t most = 10000);

  // A new handle, for a visitor without one.
  static std::string new_handle();
  // Whether a handle is one this could have made: so a cookie of any other shape is replaced.
  static bool handle_ok(std::string_view handle);

  // The CSRF token every sign-in form carries, for the visitor's handle.
  std::string csrf_token(std::string_view handle) const;
  bool csrf_ok(std::string_view handle, std::string_view token) const;

  std::optional<PreSession> find(std::string_view handle) const;
  void put(std::string_view handle, PreSession pre_session);
  void end(std::string_view handle);

 private:
  struct Held {
    PreSession pre_session;
    dannan::contract::TimePoint started;
  };

  const dannan::contract::TimeSource& _time;
  std::chrono::seconds _lifetime;
  std::size_t _most;
  SecureBuffer _key;

  mutable dannan::contract::Mutex _mutex;
  std::map<std::string, Held> _held DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::session

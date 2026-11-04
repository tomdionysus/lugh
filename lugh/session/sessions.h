//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/policy.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/status.h"
#include "lugh/directory/directory.h"
#include "lugh/scopes/grants.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::session {

// One signed-in browser (TODO/2026-11-04-oauth.md, "The Lugh session").
struct Session {
  // The store's key: the SHA-256 of the cookie's handle, in hex, so the table holds nothing
  // that works as a cookie.
  std::string key;
  std::uint64_t version = 0;

  std::string user_id;
  // What ID tokens carry for this session, never the handle.
  std::string sid;
  authn::Assurance acr = authn::Assurance::pwd;
  std::vector<std::string> amr;
  // Seconds since the epoch.
  std::uint64_t auth_time = 0;
  std::uint64_t created = 0;
  std::uint64_t last_seen = 0;
  // The secret the session's CSRF token is made from.
  SecureBuffer csrf;
  // The user's scopes as last read (refresh()), so a request is resolved from memory.
  std::vector<std::string> scopes;
  // The applications signed in through this session, by client_id: who a back-channel logout
  // tells when it ends.
  std::vector<std::string> apps;
};

// The Lugh sessions, in the sealed `sessions` table, held in memory as well so a request is
// resolved without waiting (lugh/http/caller.h). The cookie is `__Host-lugh_session`, holding
// a 256-bit random handle; only its hash is stored. A session ends when it has been idle, or
// lived, too long, when its user signs out, and when its user is removed or disabled.
//
// The scopes a session carries are its user's, read when it starts and again by refresh(),
// which the node runs every minute: someone taken out of a group loses its scopes within a
// minute, and a disabled or removed user's sessions end then.
//
// The changes take Dannan's shape (core/completion.h). Safe from any number of threads; made
// with std::make_shared.
class Sessions : public std::enable_shared_from_this<Sessions> {
 public:
  static constexpr const char* kTable = "sessions";
  static constexpr const char* kCookie = "__Host-lugh_session";
  static constexpr std::size_t kHandleBytes = 32;

  struct Settings {
    // the maintainer, 2026-11-04: 24 hours idle, 30 days at most.
    std::chrono::seconds idle{std::chrono::hours(24)};
    std::chrono::seconds absolute{std::chrono::hours(24 * 30)};
  };

  struct Created {
    Secret handle;
    Session session;
  };

  Sessions(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
           std::shared_ptr<scopes::Grants> grants, std::shared_ptr<audit::AuditLog> audit, Settings settings);

  const Settings& settings() const { return _settings; }

  // Reads every session into memory; one that has expired is left out, and removed by the
  // next refresh().
  void open(Deadline deadline, Executor executor, Done<Status> done);

  // A new session for a user who has just signed in at `acr` with `amr`.
  void create(audit::Actor actor, std::string user_id, authn::Assurance acr, std::vector<std::string> amr, Deadline deadline, Executor executor,
              Done<Outcome<Created>> done);

  // The live session the handle opens, from memory, marked as seen now. Nothing for a handle
  // that opens none, or a session expired. Never waits.
  std::optional<Session> find(std::string_view handle);

  // Whether a live session has this sid: what a refresh token's family is bound to. From
  // memory; never waits.
  bool live_sid(std::string_view sid) const;

  // The session's CSRF token, which every request through it that changes anything carries.
  static std::string csrf_token(const Session& session);
  static bool csrf_ok(const Session& session, std::string_view token);

  // Ends the session the handle opens; a handle that opens none is a success that changes
  // nothing.
  void end(audit::Actor actor, std::string handle, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // A user's live sessions, from memory, newest first.
  std::vector<Session> of_user(std::string_view user_id) const;

  // Ends the user's session with this sid; not_found for one the user does not have.
  void end_sid(audit::Actor actor, std::string user_id, std::string sid, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // Ends every session of the user's but the one with `keep` (a sid; empty keeps none): what a
  // password change, a factor reset, or an administrator does. Answers how many ended.
  void end_user(audit::Actor actor, std::string user_id, std::string keep, std::string why, Deadline deadline, Executor executor,
                Done<Outcome<std::size_t>> done);

  // Records that `client_id` signed in through the session stored under `key`, before anything
  // is issued to it, so its logout cannot be missed. not_found for a session that has ended.
  void note_app(std::string key, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // Told of every session that ends, however it ends, once it is gone from memory: where the
  // back-channel logout starts (O10b). Set before anything is served.
  void on_end(std::function<void(const Session& session, const std::string& why)> listener);

  // Each live session's user and scopes read again, and when it was last seen saved; the
  // sessions of users removed or disabled, and those expired, ended.
  void refresh(Deadline deadline, Executor executor, Done<Status> done);

  static SecureBuffer encode(const Session& session);
  static std::optional<Session> decode(std::span<const unsigned char> value);
  // The key a handle is stored under.
  static std::string key_of(std::string_view handle);

 private:
  std::uint64_t _now() const { return _wall.unix_ms() / 1000; }
  bool _live(const Session& session, std::uint64_t now) const;
  void _remove(std::string key, std::string why, Executor executor, std::function<void()> then);
  void _refresh_one(std::string key, Executor executor, std::function<void()> then);
  void _note_app(std::string key, std::string client_id, int tries, Executor executor, std::function<void(Outcome<>)> then);

  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<scopes::Grants> _grants;
  std::shared_ptr<audit::AuditLog> _audit;
  Settings _settings;

  mutable dannan::contract::Mutex _mutex;
  std::map<std::string, Session> _held DANNAN_GUARDED_BY(_mutex);
  // When each session was last written, so refresh() saves only what has moved.
  std::map<std::string, std::uint64_t> _saved_seen DANNAN_GUARDED_BY(_mutex);
  std::function<void(const Session&, const std::string&)> _on_end;
};

}  // namespace lugh::session

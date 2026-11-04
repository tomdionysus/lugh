//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "dannan/contract/time_source.h"
#include "lugh/apps/app.h"
#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/oauth/issuer.h"
#include "lugh/session/sessions.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::oauth {

// One refresh token's family: every token rotated from one code exchange.
struct Family {
  std::string id;
  std::uint64_t version = 0;

  std::string client_id;
  std::string user_id;
  // The Lugh session it came from: when that ends, so does the family.
  std::string sid;
  std::vector<std::string> scopes;
  authn::Assurance acr = authn::Assurance::pwd;
  std::vector<std::string> amr;
  std::uint64_t auth_time = 0;
  std::uint64_t created = 0;
  std::uint64_t last_used = 0;
  std::uint32_t idle_seconds = 0;
  std::uint32_t absolute_seconds = 0;
  // The SHA-256 of the current token's secret, in hex: only the newest token works.
  std::string current;
  bool revoked = false;
};

// Refresh tokens (TODO/2026-11-04-oauth.md, "Grants"; the maintainer 2026-11-04: replicated with the
// session, single use by the family's version). A token is `rt.<family>.<secret>`; the
// family is a record in the sealed `grants` table under `refresh/<family>`, holding only the
// hash of the newest secret. Rotation writes the family at the version it read, so of two
// rotations racing, the second loses and is taken as reuse; a token that is not the newest,
// presented again, is reuse too, and reuse revokes the whole family (RFC 9700 section
// 4.14.2). A family ends when its Lugh session does, when it has been idle or lived too
// long, or when it is revoked. Made with std::make_shared.
class RefreshTokens : public std::enable_shared_from_this<RefreshTokens> {
 public:
  static constexpr const char* kTable = "grants";
  static constexpr const char* kPrefix = "rt.";

  struct Rotated {
    Family family;
    std::string token;
  };

  RefreshTokens(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<session::Sessions> sessions,
                std::shared_ptr<audit::AuditLog> audit);

  // A new family for the person in `grant`, through `app`, with `scopes` as the access token
  // got: its first token.
  void issue(const apps::App& app, const CodeGrant& grant, std::vector<std::string> scopes, Deadline deadline, Executor executor,
             Done<Outcome<std::string>> done);

  // The next token for `token`, presented by `client_id`. refused (invalid_grant) for anything
  // but the family's newest token, live, of that client, whose session is live; reuse revokes
  // the family as it refuses.
  void rotate(std::string token, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<Rotated>> done);

  // The family `token` belongs to, if live and `client_id`'s, and `token` its newest.
  void inspect(std::string token, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<std::optional<Family>>> done) const;

  // Revokes the family of `token` if it is `client_id`'s; anything else changes nothing and is
  // no error (RFC 7009 section 2.2).
  void revoke(audit::Actor actor, std::string token, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<>> done);

  static SecureBuffer encode(const Family& family);
  static std::optional<Family> decode(std::span<const unsigned char> value);

 private:
  struct Parsed {
    std::string family;
    std::string secret;
  };
  static std::optional<Parsed> _parse(std::string_view token);
  void _read(std::string family, Executor executor, Done<Outcome<std::optional<Family>>> done) const;
  bool _live(const Family& family) const;
  void _revoke(Family family, std::string why, Executor executor, std::function<void()> then);

  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<session::Sessions> _sessions;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::oauth

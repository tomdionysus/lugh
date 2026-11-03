//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "dannan/contract/time_source.h"
#include "dannan/identity/crypto.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/password_hash.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/task.h"
#include "lugh/directory/directory.h"
#include "lugh/loggers/logger.h"
#include "lugh/store/store.h"
#include "lugh/system/files.h"
#include "lugh/system/random.h"

namespace lugh::authn {

// Passwords no one should use, from a local list (one per line), held as the SHA-256 of
// each folded to lower case, so the list itself is not kept in memory as text.
class BreachedPasswords {
 public:
  static constexpr std::size_t kMostFileBytes = 64 * 1024 * 1024;

  BreachedPasswords() = default;

  // Blank lines and lines starting with '#' are skipped; a trailing '\r' is dropped.
  static Task<Result<BreachedPasswords>> load(const system::Files& files, std::string path);
  static BreachedPasswords from_text(std::span<const unsigned char> text);

  bool contains(std::span<const unsigned char> password) const;
  std::size_t size() const { return _hashes.size(); }

 private:
  static std::array<unsigned char, 32> _fold_and_hash(std::span<const unsigned char> password);

  std::set<std::array<unsigned char, 32>> _hashes;
};

struct PasswordRules {
  // Counted in characters, not bytes. NIST SP 800-63B asks for 8 at least; Lugh guards
  // administrators' accounts, so asks for more.
  std::size_t least_characters = 12;
  // Argon2id would take more, but nothing longer is a password anyone types.
  std::size_t most_bytes = 256;
};

// Each user's password, as an Argon2id hash in the sealed `credentials` table, keyed by the
// user's ID. The record's version is the credential's version: P8's merge keeps the newest
// and revokes the sessions of the rest.
//
// Hashing runs on `hashing`, a pool of a few threads kept for it: each hash takes 64 MiB and
// a noticeable fraction of a second, and the caller is suspended meanwhile, holding no
// thread. The pool's size is what bounds the memory sign-ins can take at once.
class Passwords : public directory::Dependent {
 public:
  static constexpr const char* kTable = "credentials";

  Passwords(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store, std::shared_ptr<system::Random> random,
            const dannan::contract::WallClock& wall, std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs params, PasswordRules rules,
            BreachedPasswords breached);

  // Whether the password may be used by this user, and if not, why, without saying what it
  // was: too short, too long, on the breached list, or the user's own name or address.
  Outcome<> acceptable(const Secret& password, const directory::User& user) const;

  // Checks, hashes and stores it, replacing any before.
  Task<Outcome<>> set(audit::Actor actor, directory::User user, Secret password);

  // Whether it matches. A user with no password matches nothing, and costs as much to ask
  // about as one with a password, so the time taken says nothing about who exists. A
  // match under old costs is hashed again under the current ones.
  Task<bool> verify(std::string user_id, Secret password);

  // As verify() for a user who does not exist: the same work, and false.
  Task<void> spend(Secret password);

  Task<bool> has_password(std::string user_id) const;

  Task<Status> forget(audit::Actor actor, std::string user_id) override;

 private:
  std::shared_ptr<loggers::Logger> _logger;
  std::shared_ptr<store::Store> _store;
  std::shared_ptr<system::Random> _random;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<audit::AuditLog> _audit;
  Executor _hashing;
  crypto::Argon2Costs _params;
  PasswordRules _rules;
  BreachedPasswords _breached;
  // For spend(): a salt that is never anyone's.
  Bytes _decoy_salt;
};

}  // namespace lugh::authn

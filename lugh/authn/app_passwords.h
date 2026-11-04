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
#include <string_view>
#include <vector>

#include "dannan/contract/time_source.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/password_hash.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/crypto/argon2.h"
#include "lugh/directory/directory.h"
#include "lugh/network/cidr.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::authn {

// An app password as its owner or an administrator sees it: never the password or its hash.
struct AppPasswordInfo {
  // "<instance>", unique for its user.
  std::string id;
  std::string name;
  // What a bind with it may do, at most: cut at each use to what its owner's groups grant then.
  std::vector<std::string> scopes;
  // Where it may be used from; empty: anywhere.
  std::vector<std::string> networks;
  std::uint64_t created = 0;
};

// What a password that matched answers: whose, and which.
struct AppPasswordMatch {
  std::string user_id;
  AppPasswordInfo app_password;
};

// App passwords (docs/architecture.md, "LDAP and the second factor"; TODO/2026-11-04-ldap.md,
// L2): what software that cannot carry a second factor, LDAP above all, signs in with in place
// of the main password. Random, shown once, kept as an Argon2id hash, named for the device that
// uses it, limited to source networks if its creator says so, carrying a scope set (read-only by
// default, the maintainer 2026-11-04), and revocable on its own. In the sealed `app_passwords` table, keyed
// "<user>/<instance>".
//
// A password is 32 base32 characters (160 bits), shown in groups of four with dashes; dashes,
// spaces and case are ignored when it is typed. Its first four characters select the record, so
// checking a guess costs one hash.
//
// Every operation takes Dannan's shape (core/completion.h). Made with std::make_shared.
class AppPasswords : public directory::Dependent, public std::enable_shared_from_this<AppPasswords> {
 public:
  static constexpr const char* kTable = "app_passwords";
  static constexpr std::size_t kCharacters = 32;
  static constexpr std::size_t kSelectorCharacters = 4;
  static constexpr std::size_t kMostPerUser = 32;
  static constexpr std::size_t kMostScopes = 32;
  static constexpr std::size_t kMostNetworks = 16;

  // 160 random bits need no slow hash against guessing; Argon2id at OWASP's lightest, as
  // recovery codes and client secrets are, so a stolen table gives nothing up quickly either.
  static constexpr crypto::Argon2Costs kParams{19 * 1024, 2, 1};

  struct Made {
    AppPasswordInfo info;
    Secret password;
  };

  AppPasswords(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
               std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs params = kParams);

  // A new one for the user, shown once. `scopes` empty means the default, lugh:directory.read.
  // invalid for a name, scope or network that cannot be; not_found for no such user; refused
  // for a disabled user or one at the limit.
  void create(audit::Actor actor, std::string user_id, std::string name, std::vector<std::string> scopes, std::vector<std::string> networks, Deadline deadline,
              Executor executor, Done<Outcome<Made>> done);

  void list(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<AppPasswordInfo>>> done) const;

  // not_found for one the user does not have.
  void revoke(audit::Actor actor, std::string user_id, std::string id, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // The app password of the user's that `password` is, used from `source`; refused, the same
  // for every reason, when none is (a wrong password, another network, a disabled user).
  // `failed` when the store is: never a false "no".
  void verify(std::string user_id, Secret password, std::string source, Deadline deadline, Executor executor, Done<Outcome<AppPasswordMatch>> done);

  void forget(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Status> done) override;

  // As typed: dashes and spaces dropped, upper case. Nothing for what cannot be one.
  static std::optional<Secret> normal(std::string_view typed);

  struct Record {
    std::string name;
    std::string selector;
    PasswordHash hash;
    std::vector<std::string> scopes;
    std::vector<std::string> networks;
    std::uint64_t created = 0;
  };
  static SecureBuffer encode(const Record& record);
  static std::optional<Record> decode(std::span<const unsigned char> value);

 private:
  struct Stored {
    std::string key;
    Record record;
  };
  void _records(std::string user_id, Executor executor, Done<Outcome<std::vector<Stored>>> done) const;
  void _record(audit::Event event, Executor executor, std::function<void()> then) const;

  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
  Executor _hashing;
  crypto::Argon2Costs _params;
};

}  // namespace lugh::authn

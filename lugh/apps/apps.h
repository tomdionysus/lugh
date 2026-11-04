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
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dannan/contract/time_source.h"
#include "lugh/apps/app.h"
#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/crypto/argon2.h"
#include "lugh/directory/directory.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::apps {

// The applications, in the `apps` table, one record each (app.h). Only an administrator
// registers one; there is no dynamic registration. A client_id is random and never used
// again; an api's prefix is never used again either, because a removed application stays as
// a tombstone holding both, so a new one can never take an old one's grants. Every change is
// audited.
//
// Every operation takes Dannan's shape (core/completion.h). Made with std::make_shared.
class Apps : public std::enable_shared_from_this<Apps> {
 public:
  struct Settings {
    // The policy that permits client_secret_basic (docs/architecture.md: "allowed only by
    // policy"). Off unless the configuration turns it on.
    bool allow_client_secrets = false;
    // How long a rotated secret keeps working, so the application can move to the new one.
    std::chrono::seconds secret_overlap{std::chrono::hours(24)};
    // A client secret is 256 random bits, so its hash need not be slow against guessing;
    // Argon2id at OWASP's lightest, as recovery codes are.
    crypto::Argon2Costs secret_costs{19 * 1024, 2, 1};
  };

  // What creating an application, or a new secret, answers: the application, and its
  // secret where it has one, shown once.
  struct Made {
    App app;
    std::optional<Secret> secret;
  };

  static constexpr std::size_t kSecretBytes = 32;

  Apps(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
       std::shared_ptr<audit::AuditLog> audit, Executor hashing, Settings settings);

  // `draft` as validate() takes it, without client_id, version, secrets, access or roles,
  // which the application gains here and through access_set() and roles_set().
  void create(audit::Actor actor, App draft, Deadline deadline, Executor executor, Done<Outcome<Made>> done);

  // Nothing for one that does not exist or was removed.
  void app(std::string client_id, Deadline deadline, Executor executor, Done<Outcome<std::optional<App>>> done) const;
  // Every application not removed, by client_id.
  void apps(Deadline deadline, Executor executor, Done<Outcome<std::vector<App>>> done) const;

  // `changed` in place of what is stored, keeping what never changes: the client_id, kind,
  // prefix, secrets, access, roles and creation time. `expected` is the version last read.
  void replace(audit::Actor actor, App changed, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor, Done<Outcome<App>> done);

  // Whether a group's members may sign in to it. Setting what is already so changes nothing.
  void access_set(audit::Actor actor, std::string client_id, std::string group_id, bool allowed, Deadline deadline, Executor executor, Done<Outcome<App>> done);
  // The roles a group maps to for it; none clears the mapping.
  void roles_set(audit::Actor actor, std::string client_id, std::string group_id, std::vector<std::string> roles, Deadline deadline, Executor executor,
                 Done<Outcome<App>> done);

  // A new client secret, shown once; the one before keeps working for the overlap.
  void secret_rotate(audit::Actor actor, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<Made>> done);

  // Final: the record stays as a tombstone, its secrets gone, its client_id and prefix
  // never used again.
  void remove(audit::Actor actor, std::string client_id, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // The prefixes of every api not removed: the audiences there are, and the prefixes an
  // application's scopes may have.
  void prefixes(Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const;

  // Whether every application scope in `scopes` belongs to an api not removed (`own`, an
  // api's prefix being registered with them, counting as one), and every audience is lugh or
  // such an api's. invalid, naming the first that is not.
  static Outcome<> references_ok(const std::vector<std::string>& registered, const std::string& own, const std::vector<std::string>& scopes,
                                 const std::vector<std::string>& audiences);

 private:
  using Then = std::function<void()>;

  void _read(std::string client_id, Executor executor, Done<Outcome<std::optional<App>>> done) const;
  void _all(Executor executor, Done<Outcome<std::vector<App>>> done) const;
  // A change made to the stored application by `change`, which answers whether there was
  // anything to change, or why not; then written at the version read, and audited.
  void _change(audit::Actor actor, std::string client_id, std::optional<std::uint64_t> expected, std::string action,
               std::function<Outcome<bool>(App&, std::string& detail)> change, Executor executor, Done<Outcome<App>> done);
  void _put(audit::Actor actor, App app, std::uint64_t expected, std::string action, std::string detail, Executor executor, Done<Outcome<App>> done);
  // A new secret and its hash, made on the hashing pool.
  void _new_secret(Executor executor, Done<Outcome<std::pair<Secret, ClientSecret>>> done) const;

  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
  Executor _hashing;
  Settings _settings;
};

}  // namespace lugh::apps

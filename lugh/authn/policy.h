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
#include <string>
#include <string_view>

#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/task.h"
#include "lugh/directory/directory.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::authn {

// How sure Lugh is of who signed in, in increasing order (architecture.md, "Policy").
enum class Assurance : std::uint8_t {
  // A password alone.
  pwd = 1,
  // A password and a TOTP or recovery code.
  mfa = 2,
  // Phishing-resistant: WebAuthn (P11).
  phr = 3,
};

// The `acr` value, "urn:lugh:acr:mfa".
std::string_view acr(Assurance assurance);
std::optional<Assurance> assurance_from_acr(std::string_view acr);

// The level each person must reach, set globally and per group, the strictest winning, in
// the `policies` table. With nothing set, `mfa` for everyone (architecture.md, open
// question 9). Per app arrives with the apps, in P6.
//
// Every operation takes Dannan's shape (core/completion.h); a read answers `failed`, never a
// default, when the store fails or the deadline passes. Made with std::make_shared.
class Policies : public std::enable_shared_from_this<Policies> {
 public:
  static constexpr const char* kTable = "policies";
  static constexpr Assurance kDefault = Assurance::mfa;

  Policies(std::shared_ptr<store::Store> store, std::shared_ptr<directory::Directory> directory, std::shared_ptr<audit::AuditLog> audit);

  void global(Deadline deadline, Executor executor, Done<Outcome<Assurance>> done) const;
  void global_set(audit::Actor actor, Assurance level, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // nothing when the group sets nothing of its own.
  void group(std::string group_id, Deadline deadline, Executor executor, Done<Outcome<std::optional<Assurance>>> done) const;
  void group_set(audit::Actor actor, std::string group_id, std::optional<Assurance> level, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // The strictest of the global level and each of the user's groups'.
  void required(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<Assurance>> done) const;

 private:
  void _read(std::string key, Executor executor, Done<Outcome<std::optional<Assurance>>> done) const;
  void _write(audit::Actor actor, std::string key, std::optional<Assurance> level, std::string subject, Executor executor, Done<Outcome<>> done);

  store::StoreCalls _calls;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::authn

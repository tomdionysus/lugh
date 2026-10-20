#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "audit/audit_log.h"
#include "core/outcome.h"
#include "core/task.h"
#include "directory/directory.h"
#include "store/store.h"

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
class Policies {
 public:
  static constexpr const char* kTable = "policies";
  static constexpr Assurance kDefault = Assurance::mfa;

  Policies(std::shared_ptr<store::Store> store, std::shared_ptr<directory::Directory> directory, std::shared_ptr<audit::AuditLog> audit);

  Task<Assurance> global() const;
  Task<Outcome<>> global_set(audit::Actor actor, Assurance level);

  // nullopt when the group sets nothing of its own.
  Task<std::optional<Assurance>> group(std::string group_id) const;
  Task<Outcome<>> group_set(audit::Actor actor, std::string group_id, std::optional<Assurance> level);

  // The strictest of the global level and each of the user's groups'.
  Task<Assurance> required(std::string user_id) const;

 private:
  Task<std::optional<Assurance>> _read(std::string key) const;
  Task<Outcome<>> _write(audit::Actor actor, std::string key, std::optional<Assurance> level, std::string subject);

  std::shared_ptr<store::Store> _store;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::authn

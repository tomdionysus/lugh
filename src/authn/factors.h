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
#include <vector>

#include "audit/audit_log.h"
#include "authn/password_hash.h"
#include "core/outcome.h"
#include "core/secret.h"
#include "core/task.h"
#include "crypto/argon2.h"
#include "directory/directory.h"
#include "loggers/logger.h"
#include "store/store.h"
#include "system/clock.h"
#include "system/random.h"

namespace lugh::authn {

enum class FactorKind : std::uint8_t { totp = 1, recovery = 2 };

// A factor as an administrator or its owner sees it: never its secret.
struct FactorInfo {
  std::string id;
  FactorKind kind = FactorKind::totp;
  // A TOTP factor counts once a code from it has been typed back; recovery codes always do.
  bool confirmed = false;
  std::uint64_t created = 0;
  // Recovery codes not yet used.
  std::size_t remaining = 0;
};

struct TotpSetup {
  std::string factor_id;
  // For a person to type: the secret in base32.
  Secret secret;
  // For a QR code.
  Secret uri;
};

// The second factors, in the sealed `factors` table, keyed "<user>/<kind>/<instance>" (a
// removal is final, so a factor enrolled again is a new record).
//
// TOTP (RFC 6238): the secret is shown once, when it is made, and counts only once a code
// from it is typed back. The last step used is kept, and a code for that step or an
// earlier one is refused, so a code works once. Two sign-ins racing with the same code
// both read the same step, and the second write loses on its version.
//
// Recovery codes: ten, each sixteen base32 characters (80 bits), shown once and kept as
// Argon2id hashes. The first four characters select the code's slot, so a guess costs one
// hash, not ten; they are a quarter of the code, and the hash covers the whole of it.
class Factors : public directory::Dependent {
 public:
  static constexpr const char* kTable = "factors";
  static constexpr std::size_t kRecoveryCodes = 10;

  // A recovery code is 80 random bits, so the hash need not be slow against guessing; it
  // is Argon2id so that a stolen table gives nothing up quickly either. OWASP's lightest.
  static constexpr crypto::Argon2Params kRecoveryParams{19 * 1024, 2, 1};

  // `hashing` runs the recovery codes' Argon2id, as Passwords' does.
  Factors(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store, std::shared_ptr<system::Random> random,
          std::shared_ptr<system::Clock> clock, std::shared_ptr<audit::AuditLog> audit, Executor hashing,
          crypto::Argon2Params recovery_params = kRecoveryParams);

  Task<std::vector<FactorInfo>> list(std::string user_id) const;

  // Whether the user has a confirmed factor of their own. Recovery codes do not count:
  // they stand in for a factor and do not replace one.
  Task<bool> has_second_factor(std::string user_id) const;

  // A new, unconfirmed TOTP secret. Any unconfirmed one before it is removed.
  Task<Outcome<TotpSetup>> totp_begin(audit::Actor actor, std::string user_id, std::string issuer, std::string account);

  // Confirms an unconfirmed secret with a code from it. A wrong code leaves it unconfirmed.
  Task<Outcome<>> totp_confirm(audit::Actor actor, std::string user_id, std::string factor_id, std::string code);

  // Whether the code is right for any of the user's confirmed TOTP factors and not
  // already used. refused for a wrong or replayed code, failed when the store is.
  Task<Outcome<>> totp_check(std::string user_id, std::string code);

  // Ten new codes, replacing any before.
  Task<Outcome<std::vector<Secret>>> recovery_generate(audit::Actor actor, std::string user_id);

  // Uses one code: the number left afterwards. refused for a wrong or used one.
  Task<Outcome<std::size_t>> recovery_use(std::string user_id, Secret code);

  Task<Outcome<>> remove(audit::Actor actor, std::string user_id, std::string factor_id);

  // Every factor the user has, for an administrator's reset and for removal.
  Task<Status> forget(audit::Actor actor, std::string user_id) override;

 private:
  struct Stored {
    std::string key;
    std::uint64_t version = 0;
    SecureBytes value;
  };

  Task<std::vector<Stored>> _records(std::string user_id, std::optional<FactorKind> kind) const;
  std::optional<std::string> _new_key(std::string_view user_id, FactorKind kind);
  Task<void> _audit(const audit::Actor& actor, std::string action, std::string user_id, std::string detail);

  std::shared_ptr<loggers::Logger> _logger;
  std::shared_ptr<store::Store> _store;
  std::shared_ptr<system::Random> _random;
  std::shared_ptr<system::Clock> _clock;
  std::shared_ptr<audit::AuditLog> _audit_log;
  Executor _hashing;
  crypto::Argon2Params _recovery_params;
};

// The factor records, for the tests and the fuzz target.
struct TotpRecord {
  bool confirmed = false;
  std::optional<std::uint64_t> last_step;
  std::uint64_t created = 0;
  SecureBytes secret;
};

struct RecoverySlot {
  std::string selector;
  bool used = false;
  PasswordHash hash;
};

struct RecoveryRecord {
  std::uint64_t created = 0;
  std::vector<RecoverySlot> slots;
};

SecureBytes encode(const TotpRecord& record);
std::optional<TotpRecord> decode_totp(std::span<const unsigned char> value);
SecureBytes encode(const RecoveryRecord& record);
std::optional<RecoveryRecord> decode_recovery(std::span<const unsigned char> value);

// A recovery code as typed: dashes and spaces dropped, folded to upper case. nullopt for
// anything that cannot be one.
std::optional<Secret> normal_recovery_code(std::string_view code);

}  // namespace lugh::authn

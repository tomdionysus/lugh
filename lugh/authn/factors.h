//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/contract/time_source.h"
#include "dannan/status/log.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/password_hash.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/task.h"
#include "lugh/crypto/argon2.h"
#include "lugh/directory/directory.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"
#include "lugh/webauthn/ceremony.h"

namespace lugh::authn {

enum class FactorKind : std::uint8_t { totp = 1, recovery = 2, webauthn = 3 };

// A factor as an administrator or its owner sees it: never its secret.
struct FactorInfo {
  std::string id;
  FactorKind kind = FactorKind::totp;
  // A TOTP factor counts once a code from it has been typed back; recovery codes and
  // WebAuthn credentials always do.
  bool confirmed = false;
  std::uint64_t created = 0;
  // Recovery codes not yet used.
  std::size_t remaining = 0;
  // WebAuthn: the name its owner gave it, the authenticator's claimed AAGUID (hex, unverified:
  // attestation is none), whether it is a synced passkey, and when it was last used (0: never).
  std::string name;
  std::string aaguid;
  bool backed_up = false;
  std::uint64_t last_used = 0;
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
//
// Every operation takes Dannan's shape (core/completion.h); a read on a failed store or past
// its deadline is `failed`, never a wrong code or "no factor". Made with std::make_shared.
class Factors : public directory::Dependent, public std::enable_shared_from_this<Factors> {
 public:
  static constexpr const char* kTable = "factors";
  static constexpr std::size_t kRecoveryCodes = 10;

  // A recovery code is 80 random bits, so the hash need not be slow against guessing; it
  // is Argon2id so that a stolen table gives nothing up quickly either. OWASP's lightest.
  static constexpr crypto::Argon2Costs kRecoveryParams{19 * 1024, 2, 1};

  // `hashing` runs the recovery codes' Argon2id, as Passwords' does.
  Factors(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
          std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs recovery_params = kRecoveryParams);

  void list(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<FactorInfo>>> done) const;

  // Whether the user has a confirmed factor of their own: a confirmed TOTP secret or a
  // WebAuthn credential. Recovery codes do not count: they stand in for a factor and do not
  // replace one.
  void has_second_factor(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<bool>> done) const;

  // A new, unconfirmed TOTP secret. Any unconfirmed one before it is removed.
  void totp_begin(audit::Actor actor, std::string user_id, std::string issuer, std::string account, Deadline deadline, Executor executor,
                  Done<Outcome<TotpSetup>> done);

  // Confirms an unconfirmed secret with a code from it. A wrong code leaves it unconfirmed.
  void totp_confirm(audit::Actor actor, std::string user_id, std::string factor_id, std::string code, Deadline deadline, Executor executor,
                    Done<Outcome<>> done);

  // Whether the code is right for any of the user's confirmed TOTP factors and not
  // already used. refused for a wrong or replayed code, failed when the store is.
  void totp_check(std::string user_id, std::string code, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // Ten new codes, replacing any before.
  void recovery_generate(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<Secret>>> done);

  // Uses one code: the number left afterwards. refused for a wrong or used one.
  void recovery_use(std::string user_id, Secret code, Deadline deadline, Executor executor, Done<Outcome<std::size_t>> done);

  // A WebAuthn credential from a registration ceremony (W3C WebAuthn 7.1), named by its owner.
  // Refused when the ceremony fails its checks, and when the credential id is registered
  // already, to this user or any other (7.1, step 26).
  void webauthn_register(audit::Actor actor, std::string user_id, std::string name, webauthn::Expected expected, Bytes client_data_json,
                         Bytes attestation_object, Deadline deadline, Executor executor, Done<Outcome<FactorInfo>> done);

  // The user's credential ids, for a ceremony's allowCredentials.
  void webauthn_credentials(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const;

  // An assertion (7.2) by the user's credential `credential_id`. The sign count and last use
  // are written at the version read, so two sign-ins racing with one assertion cannot both
  // pass. refused for a check that fails, a credential that is not the user's, or a lost race.
  void webauthn_check(std::string user_id, webauthn::Expected expected, std::string credential_id, Bytes client_data_json, Bytes authenticator_data,
                      Bytes signature, Deadline deadline, Executor executor, Done<Outcome<webauthn::Asserted>> done);

  // A new name for one of the user's WebAuthn credentials: 1 to 64 printable bytes. not_found for
  // anything else, conflict when it changed between the read and the write.
  void webauthn_rename(audit::Actor actor, std::string user_id, std::string factor_id, std::string name, Deadline deadline, Executor executor,
                       Done<Outcome<FactorInfo>> done);

  void remove(audit::Actor actor, std::string user_id, std::string factor_id, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // Every factor the user has, for an administrator's reset and for removal.
  void forget(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Status> done) override;

 private:
  struct Stored {
    std::string key;
    std::uint64_t version = 0;
    SecureBuffer value;
  };

  void _records(std::string user_id, std::optional<FactorKind> kind, Executor executor, Done<Outcome<std::vector<Stored>>> done) const;
  std::optional<std::string> _new_key(std::string_view user_id, FactorKind kind);
  void _record(const audit::Actor& actor, std::string action, std::string user_id, std::string detail, Executor executor, std::function<void()> then) const;

  dannan::status::ScopedLogger _logger;
  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<audit::AuditLog> _audit_log;
  Executor _hashing;
  crypto::Argon2Costs _recovery_params;
};

// The factor records, for the tests and the fuzz target.
struct TotpRecord {
  bool confirmed = false;
  std::optional<std::uint64_t> last_step;
  std::uint64_t created = 0;
  SecureBuffer secret;
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

struct WebAuthnRecord {
  std::uint64_t created = 0;
  std::uint64_t last_used = 0;
  std::string name;
  std::string credential_id;
  webauthn::PublicKey key;
  std::uint32_t sign_count = 0;
  bool backup_eligible = false;
  bool backed_up = false;
  std::array<std::uint8_t, 16> aaguid{};
};

SecureBuffer encode(const TotpRecord& record);
SecureBuffer encode(const WebAuthnRecord& record);
std::optional<WebAuthnRecord> decode_webauthn(std::span<const unsigned char> value);
std::optional<TotpRecord> decode_totp(std::span<const unsigned char> value);
SecureBuffer encode(const RecoveryRecord& record);
std::optional<RecoveryRecord> decode_recovery(std::span<const unsigned char> value);

// A recovery code as typed: dashes and spaces dropped, folded to upper case. nullopt for
// anything that cannot be one.
std::optional<Secret> normal_recovery_code(std::string_view code);

}  // namespace lugh::authn

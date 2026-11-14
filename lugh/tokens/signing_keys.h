//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/audit/audit_log.h"
#include "lugh/client/jose.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/status.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::tokens {

using client::public_jwk;
using client::SigningAlgorithm;
using client::SigningKey;
using client::VerifyKey;

// One signing key as an administrator sees it: never its private part.
struct KeyInfo {
  std::string kid;
  SigningAlgorithm algorithm = SigningAlgorithm::es256;
  // Seconds since the epoch. A key is published from `created`, signs from `active_from`,
  // and is withdrawn from JWKS at `retired_at` (zero: not yet).
  std::uint64_t created = 0;
  std::uint64_t active_from = 0;
  std::uint64_t retired_at = 0;
};

// What signs: a kid and its key.
struct Signer {
  std::string kid;
  std::shared_ptr<const SigningKey> key;
};

// The token signing keys (docs/architecture.md, "OAuth profile"), one record each in the
// sealed `signing_keys` table, keyed by kid. ES256 signs by default and EdDSA where an
// application asks for it, so there is a current key of each. A new key is published in
// JWKS before anything is signed with it (`lead`), and the key it replaces is withdrawn only
// once every token it signed has expired (`retire_after` its successor starts). Nothing is
// ever deleted: a retired key stays, retired.
//
// Every key is held in memory once open(), so signing and publishing never wait. The
// changes take Dannan's shape (core/completion.h). Safe from any number of threads; made
// with std::make_shared.
class SigningKeys : public std::enable_shared_from_this<SigningKeys> {
 public:
  static constexpr const char* kTable = "signing_keys";

  struct Settings {
    // How long a new key is published before it signs, so every verifier has fetched it.
    std::chrono::seconds lead{std::chrono::hours(1)};
    // How long the key before it stays published after the new one starts signing: longer
    // than any token lives (an hour at most).
    std::chrono::seconds retire_after{std::chrono::hours(2)};
    // A key signs for this long before rotate_due() replaces it.
    std::chrono::seconds rotate_every{std::chrono::hours(24 * 90)};
  };

  SigningKeys(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<audit::AuditLog> audit, Settings settings);

  // Reads every key into memory, and makes one of each algorithm, signing at once, where
  // there is none: on a new cluster's first start.
  void open(Deadline deadline, Executor executor, Done<Status> done);

  // The key to sign with now; nothing before open(), or if no key of that algorithm signs
  // yet. Never waits.
  std::optional<Signer> signer(SigningAlgorithm algorithm = SigningAlgorithm::es256) const;

  // Every key published now, those not yet signing among them, by kid: what verifies a
  // token.
  std::vector<VerifyKey> published() const;
  // The same, as a JWK Set (RFC 7517 section 5).
  boost::json::object jwks() const;
  // Every key, retired ones too, newest first.
  std::vector<KeyInfo> keys() const;

  // A new key of `algorithm`, published now and signing after the lead; the current one is
  // withdrawn `retire_after` that. Audited.
  void rotate(audit::Actor actor, SigningAlgorithm algorithm, Deadline deadline, Executor executor, Done<Outcome<KeyInfo>> done);

  // rotate() for each algorithm whose newest key has signed for `rotate_every`.
  void rotate_due(Deadline deadline, Executor executor, Done<Status> done);

  struct Record {
    SigningAlgorithm algorithm = SigningAlgorithm::es256;
    SecureBuffer pkcs8;
    std::uint64_t created = 0;
    std::uint64_t active_from = 0;
    std::uint64_t retired_at = 0;
  };
  static SecureBuffer encode(const Record& record);
  static std::optional<Record> decode(std::span<const unsigned char> value);

 private:
  struct Held {
    KeyInfo info;
    std::uint64_t version = 0;
    std::shared_ptr<const SigningKey> key;
    Bytes public_key;
  };

  std::uint64_t _now() const { return _wall.unix_ms() / 1000; }
  // A new key of `algorithm` signing from `active_from`, written and held.
  void _make(audit::Actor actor, SigningAlgorithm algorithm, std::uint64_t active_from, Executor executor, Done<Outcome<KeyInfo>> done);
  // The newest key of `algorithm` not retired, from what is held.
  std::optional<Held> _newest(SigningAlgorithm algorithm) const;

  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<audit::AuditLog> _audit;
  Settings _settings;

  mutable dannan::contract::Mutex _mutex;
  std::vector<Held> _held DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::tokens

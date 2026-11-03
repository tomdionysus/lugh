//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"
#include "lugh/core/task.h"
#include "lugh/crypto/argon2.h"
#include "lugh/keys/keyring.h"
#include "lugh/loggers/logger.h"
#include "lugh/system/console.h"
#include "lugh/system/environment.h"
#include "lugh/system/files.h"
#include "lugh/system/random.h"

namespace lugh::keys {

// The name of the systemd credential that holds a node's master key, as the unit's
// LoadCredentialEncrypted= gives it.
inline constexpr const char* kCredentialName = "lugh-master-key";

// A passphrase is all that stands between a stolen disk and the keys: no shorter than this.
inline constexpr std::size_t kShortestPassphrase = 16;

// The keyring in the state directory: making it (`lugh-node init`), finding its master key, and
// opening it at start.
class KeyringManager {
 public:
  static constexpr const char* kFileName = "keyring";

  // `hashing` runs Argon2id over a passphrase, which takes its whole 64 MiB and a while.
  KeyringManager(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<system::Files> files, std::shared_ptr<system::Random> random,
                 std::shared_ptr<system::Console> console, std::shared_ptr<system::Environment> environment, std::string state_directory, Executor hashing);

  std::string path() const;

  struct Created {
    Keyring keyring;
    SecureBytes master_key;
  };

  // `lugh-node init`: a new master key and an empty keyring under it, not yet saved. The caller
  // hands the key to systemd-creds and then calls save_new(), so a key that never reached
  // its credential leaves nothing behind. Refused if there is a keyring already.
  Task<Result<Created>> create_for_credential();

  // `lugh-node init --passphrase`: asks for a passphrase twice, stretches it with Argon2id into
  // the master key, and saves the new keyring.
  Task<Result<Keyring>> create_with_passphrase(crypto::Argon2Params params);

  // Saves a keyring where there is none, refusing to replace one.
  Task<Status> save_new(const Keyring& keyring);

  // Saves a keyring over the one there.
  Task<Status> save(const Keyring& keyring);

  // At start: reads the keyring, finds the master key it was made for (the credential, or
  // the passphrase, asked for), and opens it.
  Task<Result<Keyring>> open();

 private:
  Task<Status> _refuse_existing() const;
  Task<Result<SecureBytes>> _from_credential() const;
  Task<Result<SecureBytes>> _from_passphrase(KeyringHeader header);

  std::shared_ptr<loggers::Logger> _logger;
  std::shared_ptr<system::Files> _files;
  std::shared_ptr<system::Random> _random;
  std::shared_ptr<system::Console> _console;
  std::shared_ptr<system::Environment> _environment;
  std::string _state_directory;
  Executor _hashing;
};

}  // namespace lugh::keys

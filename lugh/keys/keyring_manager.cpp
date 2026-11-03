//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/keys/keyring_manager.h"

#include <utility>

#include "lugh/loggers/logger_scoped.h"

namespace lugh::keys {

namespace {

// A credential is the 32 bytes and nothing else; a little room to say how wrong it is.
constexpr std::size_t kMostCredentialBytes = 4096;

}  // namespace

KeyringManager::KeyringManager(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<system::Files> files, std::shared_ptr<system::Random> random,
                               std::shared_ptr<system::Console> console, std::shared_ptr<system::Environment> environment, std::string state_directory,
                               Executor hashing)
    : _logger(std::make_shared<loggers::LoggerScoped>("keys", std::move(logger))),
      _files(std::move(files)),
      _random(std::move(random)),
      _console(std::move(console)),
      _environment(std::move(environment)),
      _state_directory(std::move(state_directory)),
      _hashing(std::move(hashing)) {}

std::string KeyringManager::path() const { return _state_directory + "/" + kFileName; }

Task<Status> KeyringManager::_refuse_existing() const {
  if (co_await _files->exists(path())) {
    co_return Status::failure("there is a keyring at " + path() + " already; init would orphan everything sealed under it, so it is never replaced");
  }
  co_return Status::success();
}

Task<Result<KeyringManager::Created>> KeyringManager::create_for_credential() {
  using Answer = Result<Created>;
  if (const auto refused = co_await _refuse_existing(); !refused.ok) co_return Answer::failure(refused.error);

  KeyringHeader header;
  header.source = MasterKeySource::credential;
  header.id = _random->bytes(kKeyringIdBytes);
  if (header.id.size() != kKeyringIdBytes) co_return Answer::failure("no randomness for a keyring id");

  SecureBuffer master_key(kMasterKeyBytes);
  if (!_random->fill(master_key)) co_return Answer::failure("no randomness for a master key");

  auto keyring = Keyring::create(std::move(header), master_key);
  if (!keyring.ok) co_return Answer::failure(keyring.error);

  co_return Answer::success(Created{std::move(keyring.value), std::move(master_key)});
}

Task<Result<Keyring>> KeyringManager::create_with_passphrase(crypto::Argon2Costs params) {
  using Answer = Result<Keyring>;
  if (const auto refused = co_await _refuse_existing(); !refused.ok) co_return Answer::failure(refused.error);

  auto passphrase = co_await _console->read_secret("New master passphrase: ");
  if (!passphrase) co_return Answer::failure("no passphrase given");
  if (passphrase->size() < kShortestPassphrase) {
    co_return Answer::failure("a master passphrase is at least " + std::to_string(kShortestPassphrase) + " characters");
  }

  const auto again = co_await _console->read_secret("Again: ");
  if (!again || !again->equals(*passphrase)) co_return Answer::failure("the passphrases differ");

  KeyringHeader header;
  header.source = MasterKeySource::passphrase;
  header.id = _random->bytes(kKeyringIdBytes);
  header.salt = _random->bytes(kPassphraseSaltBytes);
  header.argon2 = params;
  if (header.id.size() != kKeyringIdBytes || header.salt.size() != kPassphraseSaltBytes) co_return Answer::failure("no randomness for a keyring");

  auto master_key = co_await offload(_hashing, [params, salt = header.salt, passphrase = std::move(*passphrase)] {
    return crypto::stretch(byte_span(passphrase.reveal()), salt, params, kMasterKeyBytes);
  });
  if (!master_key.ok) co_return Answer::failure(master_key.error);

  auto keyring = Keyring::create(std::move(header), master_key.value);
  if (!keyring.ok) co_return keyring;

  if (const auto saved = co_await save_new(keyring.value); !saved.ok) co_return Answer::failure(saved.error);
  co_return keyring;
}

Task<Status> KeyringManager::save_new(const Keyring& keyring) {
  if (const auto made = co_await _files->make_directory(_state_directory); !made.ok) co_return made;

  auto sealed = keyring.seal();
  if (!sealed.ok) co_return Status::failure(sealed.error);
  if (const auto written = co_await _files->write(path(), std::move(sealed.value), false); !written.ok) co_return written;

  _logger->info("Made keyring " + keyring.id_hex() + " at " + path());
  co_return Status::success();
}

Task<Status> KeyringManager::save(const Keyring& keyring) {
  auto sealed = keyring.seal();
  if (!sealed.ok) co_return Status::failure(sealed.error);
  co_return co_await _files->write(path(), std::move(sealed.value), true);
}

Task<Result<Keyring>> KeyringManager::open() {
  using Answer = Result<Keyring>;

  if (!co_await _files->exists(path())) co_return Answer::failure("no keyring at " + path() + ": run `lugh-node init` first");

  const auto file = co_await _files->read(path(), kMostKeyringBytes);
  if (!file.ok) co_return Answer::failure(file.error);

  const auto parsed = decode_header(file.value);
  if (!parsed) co_return Answer::failure(path() + " is not a Lugh keyring");

  auto master_key = parsed->header.source == MasterKeySource::credential ? co_await _from_credential() : co_await _from_passphrase(parsed->header);
  if (!master_key.ok) co_return Answer::failure(master_key.error);

  auto keyring = Keyring::open(file.value, master_key.value);
  if (!keyring.ok) co_return Answer::failure(path() + ": " + keyring.error);

  _logger->info("Opened keyring " + keyring.value.id_hex() + " at " + path() + ", holding " + std::to_string(keyring.value.size()) + " data keys");
  co_return keyring;
}

Task<Result<SecureBuffer>> KeyringManager::_from_credential() const {
  using Answer = Result<SecureBuffer>;

  const auto directory = _environment->get("CREDENTIALS_DIRECTORY");
  if (!directory || directory->empty()) {
    co_return Answer::failure(std::string("the keyring's master key is the systemd credential ") + kCredentialName +
                              ", and there is no $CREDENTIALS_DIRECTORY: start Lugh from its unit, which loads it");
  }

  const auto credential = *directory + "/" + kCredentialName;
  if (!co_await _files->exists(credential)) co_return Answer::failure(std::string("no credential ") + kCredentialName + " in " + *directory);

  auto key = co_await _files->read_secret(credential, kMostCredentialBytes);
  if (!key.ok) co_return key;
  if (key.value.size() != kMasterKeyBytes) {
    co_return Answer::failure(std::string("the credential ") + kCredentialName + " is " + std::to_string(key.value.size()) + " bytes; a master key is " +
                              std::to_string(kMasterKeyBytes));
  }
  co_return key;
}

Task<Result<SecureBuffer>> KeyringManager::_from_passphrase(KeyringHeader header) {
  auto passphrase = co_await _console->read_secret("Lugh master passphrase: ");
  if (!passphrase) co_return Result<SecureBuffer>::failure("the keyring's master key is a passphrase, and none was given");
  co_return co_await offload(_hashing, [header = std::move(header), passphrase = std::move(*passphrase)] {
    return crypto::stretch(byte_span(passphrase.reveal()), header.salt, header.argon2, kMasterKeyBytes);
  });
}

}  // namespace lugh::keys

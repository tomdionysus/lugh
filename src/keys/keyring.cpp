#include "keys/keyring.h"

#include <utility>

#include "crypto/aead.h"
#include "crypto/hkdf.h"

namespace lugh::keys {

namespace {

constexpr std::string_view kKekInfo = "lugh keyring v1 kek";

}  // namespace

Status Keyring::_check(const KeyringHeader& header) {
  if (header.id.size() != kKeyringIdBytes) return Status::failure("a keyring id is 16 bytes");
  if (header.source == MasterKeySource::passphrase) {
    if (header.salt.size() != kPassphraseSaltBytes) return Status::failure("a passphrase salt is 16 bytes");
    if (!header.argon2.valid()) return Status::failure("the passphrase's Argon2id costs are out of range");
  }
  return Status::success();
}

Result<SecureBytes> Keyring::_derive_kek(const KeyringHeader& header, std::span<const unsigned char> master_key) {
  if (master_key.size() != kMasterKeyBytes) return Result<SecureBytes>::failure("a master key is 32 bytes");
  return crypto::hkdf_sha256(master_key, header.id, byte_span(kKekInfo), crypto::kAeadKeyBytes);
}

Result<Keyring> Keyring::create(KeyringHeader header, std::span<const unsigned char> master_key) {
  using Answer = Result<Keyring>;
  if (const auto checked = _check(header); !checked.ok) return Answer::failure(checked.error);

  auto kek = _derive_kek(header, master_key);
  if (!kek.ok) return Answer::failure(kek.error);

  Keyring keyring;
  keyring._header = std::move(header);
  keyring._kek = std::move(kek.value);
  return Answer::success(std::move(keyring));
}

Result<Keyring> Keyring::open(std::span<const unsigned char> file, std::span<const unsigned char> master_key) {
  using Answer = Result<Keyring>;

  auto parsed = decode_header(file);
  if (!parsed) return Answer::failure("not a Lugh keyring");

  auto kek = _derive_kek(parsed->header, master_key);
  if (!kek.ok) return Answer::failure(kek.error);

  const auto associated = file.first(parsed->length);
  const auto body = crypto::open(kek.value, file.subspan(parsed->length), associated);
  if (!body) return Answer::failure("the master key does not open the keyring: it is the wrong key, or the file has been altered");

  auto keys = decode_body(*body);
  if (!keys) return Answer::failure("the keyring opened but its contents are malformed");

  Keyring keyring;
  keyring._header = std::move(parsed->header);
  keyring._kek = std::move(kek.value);
  keyring._keys = std::move(*keys);
  return Answer::success(std::move(keyring));
}

Result<Bytes> Keyring::seal(system::Random& random) const {
  using Answer = Result<Bytes>;
  if (_kek.empty()) return Answer::failure("the keyring has no KEK");

  auto file = encode_header(_header);
  const auto body = encode_body(_keys);
  auto sealed = crypto::seal(_kek, body, file, random);
  if (!sealed.ok) return Answer::failure("cannot seal the keyring: " + sealed.error);

  file.insert(file.end(), sealed.value.begin(), sealed.value.end());
  return Answer::success(std::move(file));
}

std::string Keyring::id_hex() const {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  for (const auto byte : _header.id) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0f]);
  }
  return out;
}

const DataKey* Keyring::current(std::string_view name) const {
  const DataKey* newest = nullptr;
  for (const auto& key : _keys) {
    if (key.name == name && (newest == nullptr || key.epoch > newest->epoch)) newest = &key;
  }
  return newest;
}

const DataKey* Keyring::find(std::string_view name, std::uint32_t epoch) const {
  for (const auto& key : _keys) {
    if (key.name == name && key.epoch == epoch) return &key;
  }
  return nullptr;
}

Result<std::uint32_t> Keyring::rotate(std::string_view name, system::Random& random) {
  using Answer = Result<std::uint32_t>;
  if (!valid_key_name(name)) return Answer::failure("a data key's name is 1 to 64 of a-z, 0-9 and _");
  if (_keys.size() >= kMostDataKeys) return Answer::failure("the keyring is full");

  const auto* newest = current(name);
  if (newest != nullptr && newest->epoch == UINT32_MAX) return Answer::failure("no epoch is left for " + std::string(name));
  const std::uint32_t epoch = newest == nullptr ? 1 : newest->epoch + 1;

  DataKey key;
  key.name = std::string(name);
  key.epoch = epoch;
  key.key.resize(kDataKeyBytes);
  if (!random.fill(key.key)) return Answer::failure("no randomness for a data key");

  _keys.push_back(std::move(key));
  return Answer::success(epoch);
}

Status Keyring::add(DataKey key) {
  if (!valid_key_name(key.name)) return Status::failure("a data key's name is 1 to 64 of a-z, 0-9 and _");
  if (key.epoch == 0) return Status::failure("epochs start at 1");
  if (key.key.size() != kDataKeyBytes) return Status::failure("a data key is 32 bytes");
  if (find(key.name, key.epoch) != nullptr) return Status::failure("the keyring already holds " + key.name + " epoch " + std::to_string(key.epoch));
  if (_keys.size() >= kMostDataKeys) return Status::failure("the keyring is full");

  _keys.push_back(std::move(key));
  return Status::success();
}

Status Keyring::rekey(KeyringHeader header, std::span<const unsigned char> master_key) {
  if (const auto checked = _check(header); !checked.ok) return checked;

  auto kek = _derive_kek(header, master_key);
  if (!kek.ok) return Status::failure(kek.error);

  _header = std::move(header);
  _kek = std::move(kek.value);
  return Status::success();
}

}  // namespace lugh::keys

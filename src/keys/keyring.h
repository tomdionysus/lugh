#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/secure_bytes.h"
#include "core/status.h"
#include "keys/keyring_format.h"
#include "system/random.h"

namespace lugh::keys {

inline constexpr std::size_t kMasterKeyBytes = 32;

// A node's keyring: the cluster's data encryption keys, held under this node's KEK. The
// KEK is derived from the master key, which is dropped once that is done; the keyring keeps
// the KEK, because sealing the file again after a rotation needs it.
//
// Not thread-safe. The store, which is its one user, serialises changes.
class Keyring {
 public:
  // Empty, and with no KEK: what a failed Result holds.
  Keyring() = default;

  // A new keyring with no data keys, for a master key of kMasterKeyBytes.
  static Result<Keyring> create(KeyringHeader header, std::span<const unsigned char> master_key);

  // A keyring file opened with its master key. A wrong key and an altered file are the
  // same failure: neither can be told from the other, and neither should be trusted.
  static Result<Keyring> open(std::span<const unsigned char> file, std::span<const unsigned char> master_key);

  // The file, sealed again under a fresh nonce.
  Result<Bytes> seal(system::Random& random) const;

  const KeyringHeader& header() const { return _header; }

  // The id, in hex, for a log line: it is not secret.
  std::string id_hex() const;

  std::size_t size() const { return _keys.size(); }

  // The newest epoch of a name, or null when there is none.
  const DataKey* current(std::string_view name) const;

  const DataKey* find(std::string_view name, std::uint32_t epoch) const;

  // A new key for the name, one epoch past the newest (the first is epoch 1). The answer is
  // the new epoch.
  Result<std::uint32_t> rotate(std::string_view name, system::Random& random);

  // A key made elsewhere: another node's, delivered when this one joins.
  Status add(DataKey key);

  // The same data keys under a new master key: rotating this node's master key, or moving
  // it from a passphrase to a credential. Nothing is re-sealed but this file.
  Status rekey(KeyringHeader header, std::span<const unsigned char> master_key);

 private:
  static Result<SecureBytes> _derive_kek(const KeyringHeader& header, std::span<const unsigned char> master_key);
  static Status _check(const KeyringHeader& header);

  KeyringHeader _header;
  SecureBytes _kek;
  std::vector<DataKey> _keys;
};

}  // namespace lugh::keys

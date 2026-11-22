//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The keyring's two parsers: the header, read before anything is decrypted and so open to
// whoever can write the file, and the body, read after. The first byte picks which, so one
// corpus covers both.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/fuzz/target.h"
#include "lugh/keys/keyring_format.h"

namespace {

int run(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::span<const unsigned char> input(data + 1, size - 1);

  if (data[0] & 1) {
    const auto parsed = lugh::keys::decode_header(input);
    // What parses must say the same when written again.
    if (parsed) {
      const auto again = lugh::keys::encode_header(parsed->header);
      if (again.size() != parsed->length || !std::equal(again.begin(), again.end(), input.begin()))
        lugh::fuzz::finding("a keyring header that does not write back as itself");
    }
  } else {
    const auto keys = lugh::keys::decode_body(input);
    if (keys) {
      const auto again = lugh::keys::encode_body(*keys);
      if (again.size() != input.size() || !std::equal(again.begin(), again.end(), input.begin()))
        lugh::fuzz::finding("a keyring body that does not write back as itself");
    }
  }
  return 0;
}

// Made by the writers themselves, so they follow the format: a credential's header and a
// passphrase's (odd first byte), and a body of two keys (even).
std::vector<lugh::fuzz::Bytes> seeds() {
  using namespace lugh::keys;
  KeyringHeader credential;
  credential.id = lugh::Bytes(kKeyringIdBytes, 0x11);
  KeyringHeader passphrase = credential;
  passphrase.source = MasterKeySource::passphrase;
  passphrase.salt = lugh::Bytes(kPassphraseSaltBytes, 0x22);

  std::vector<DataKey> keys;
  keys.push_back({"users", 1, lugh::SecureBuffer(kDataKeyBytes, 0x33)});
  keys.push_back({"groups", 2, lugh::SecureBuffer(kDataKeyBytes, 0x44)});
  return {lugh::fuzz::selected(1, encode_header(credential)), lugh::fuzz::selected(1, encode_header(passphrase)), lugh::fuzz::selected(0, encode_body(keys))};
}

const dannan::fuzz::Registration registered("keyring", [](std::span<const std::uint8_t> input) { run(input.data(), input.size()); }, seeds);

}  // namespace

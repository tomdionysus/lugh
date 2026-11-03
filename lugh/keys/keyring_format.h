//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "lugh/core/secure_bytes.h"
#include "lugh/crypto/argon2.h"

namespace lugh::keys {

// Where a keyring's master key comes from: a systemd credential, or a passphrase typed at
// start on a host without one.
enum class MasterKeySource : std::uint8_t { credential = 1, passphrase = 2 };

inline constexpr std::size_t kKeyringIdBytes = 16;
inline constexpr std::size_t kPassphraseSaltBytes = 16;
inline constexpr std::size_t kDataKeyBytes = 32;
inline constexpr std::size_t kMostDataKeys = 16384;
inline constexpr std::size_t kMostKeyNameBytes = 64;
inline constexpr std::size_t kMostKeyringBytes = 2 * 1024 * 1024;

// What a keyring says before it is opened: enough to find its master key and nothing more.
// It is bound into the seal as associated data, so it cannot be edited unnoticed.
struct KeyringHeader {
  MasterKeySource source = MasterKeySource::credential;

  // Random, and the salt of the KEK's derivation, so two keyrings under one master key
  // still have different KEKs.
  Bytes id;

  // For a passphrase only: the costs and salt it is stretched with.
  crypto::Argon2Params argon2;
  Bytes salt;
};

// A data encryption key: one per table and epoch, the same on every node. A new epoch is a
// rotation; old epochs stay until compaction has re-sealed everything under them.
struct DataKey {
  std::string name;
  std::uint32_t epoch = 0;
  SecureBytes key;
};

// Lower-case letters, digits and underscores, 1 to 64 of them: a table name.
bool valid_key_name(std::string_view name);

// The file is
//
//   "LUGHKEYS"  8
//   version     1   (1)
//   source      1   (1 credential, 2 passphrase)
//   id          16
//   passphrase only:
//     memory    4   KiB, big-endian
//     passes    4
//     lanes     4
//     salt      16
//   sealed      the rest: AES-256-GCM under the KEK, the bytes above as associated data
//
// and the sealed body is
//
//   count       4
//   count times:
//     name      1 length, then the name
//     epoch     4
//     key       1 length (32), then the key
//
// Every parse refuses a short field, a trailing byte, a value out of range and a
// duplicate; the parsers are fuzzed (fuzz/keyring_fuzz.cpp).

Bytes encode_header(const KeyringHeader& header);

struct ParsedHeader {
  KeyringHeader header;
  // Where the sealed body starts.
  std::size_t length = 0;
};

std::optional<ParsedHeader> decode_header(std::span<const unsigned char> file);

SecureBytes encode_body(const std::vector<DataKey>& keys);
std::optional<std::vector<DataKey>> decode_body(std::span<const unsigned char> body);

}  // namespace lugh::keys

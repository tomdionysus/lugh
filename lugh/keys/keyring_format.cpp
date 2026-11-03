//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/keys/keyring_format.h"

#include <algorithm>
#include <set>
#include <utility>

#include "lugh/core/byte_io.h"

namespace lugh::keys {

namespace {

constexpr std::string_view kMagic = "LUGHKEYS";
constexpr std::uint8_t kVersion = 1;

}  // namespace

bool valid_key_name(std::string_view name) {
  if (name.empty() || name.size() > kMostKeyNameBytes) return false;
  for (const char c : name) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
  }
  return true;
}

Bytes encode_header(const KeyringHeader& header) {
  Bytes out;
  ByteWriter writer(out);
  writer.text(kMagic);
  writer.u8(kVersion);
  writer.u8(static_cast<std::uint8_t>(header.source));
  writer.bytes(header.id);
  if (header.source == MasterKeySource::passphrase) {
    writer.u32(header.argon2.memory_kib);
    writer.u32(header.argon2.iterations);
    writer.u32(header.argon2.lanes);
    writer.bytes(header.salt);
  }
  return out;
}

std::optional<ParsedHeader> decode_header(std::span<const unsigned char> file) {
  if (file.size() > kMostKeyringBytes) return std::nullopt;
  ByteReader reader(file);

  const auto magic = reader.bytes(kMagic.size());
  if (!magic || !std::equal(magic->begin(), magic->end(), kMagic.begin())) return std::nullopt;
  if (reader.u8() != kVersion) return std::nullopt;

  ParsedHeader parsed;
  const auto source = reader.u8();
  if (source == static_cast<std::uint8_t>(MasterKeySource::credential)) {
    parsed.header.source = MasterKeySource::credential;
  } else if (source == static_cast<std::uint8_t>(MasterKeySource::passphrase)) {
    parsed.header.source = MasterKeySource::passphrase;
  } else {
    return std::nullopt;
  }

  const auto id = reader.bytes(kKeyringIdBytes);
  if (!id) return std::nullopt;
  parsed.header.id.assign(id->begin(), id->end());

  if (parsed.header.source == MasterKeySource::passphrase) {
    const auto memory = reader.u32();
    const auto iterations = reader.u32();
    const auto lanes = reader.u32();
    const auto salt = reader.bytes(kPassphraseSaltBytes);
    if (!memory || !iterations || !lanes || !salt) return std::nullopt;
    parsed.header.argon2 = crypto::Argon2Params{*memory, *iterations, *lanes};
    if (!parsed.header.argon2.valid()) return std::nullopt;
    parsed.header.salt.assign(salt->begin(), salt->end());
  }

  parsed.length = reader.offset();
  return parsed;
}

SecureBytes encode_body(const std::vector<DataKey>& keys) {
  SecureBytes out;
  ByteWriter writer(out);
  writer.u32(static_cast<std::uint32_t>(keys.size()));
  for (const auto& key : keys) {
    writer.u8(static_cast<std::uint8_t>(key.name.size()));
    writer.text(key.name);
    writer.u32(key.epoch);
    writer.u8(static_cast<std::uint8_t>(key.key.size()));
    writer.bytes(key.key);
  }
  return out;
}

std::optional<std::vector<DataKey>> decode_body(std::span<const unsigned char> body) {
  ByteReader reader(body);

  const auto count = reader.u32();
  if (!count || *count > kMostDataKeys) return std::nullopt;

  std::vector<DataKey> keys;
  std::set<std::pair<std::string, std::uint32_t>> seen;
  for (std::uint32_t i = 0; i < *count; ++i) {
    DataKey key;

    const auto name_length = reader.u8();
    if (!name_length) return std::nullopt;
    const auto name = reader.bytes(*name_length);
    if (!name) return std::nullopt;
    key.name.assign(name->begin(), name->end());
    if (!valid_key_name(key.name)) return std::nullopt;

    const auto epoch = reader.u32();
    if (!epoch || *epoch == 0) return std::nullopt;
    key.epoch = *epoch;

    if (reader.u8() != kDataKeyBytes) return std::nullopt;
    const auto material = reader.bytes(kDataKeyBytes);
    if (!material) return std::nullopt;
    key.key.assign(material->begin(), material->end());

    if (!seen.emplace(key.name, key.epoch).second) return std::nullopt;
    keys.push_back(std::move(key));
  }

  if (!reader.done()) return std::nullopt;
  return keys;
}

}  // namespace lugh::keys

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

#include "lugh/core/codec.h"

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
  dannan::net::Writer writer;
  writer.raw(byte_span(kMagic));
  writer.u8(kVersion);
  writer.u8(static_cast<std::uint8_t>(header.source));
  writer.raw(header.id);
  if (header.source == MasterKeySource::passphrase) {
    writer.u32(header.argon2.memory_kib);
    writer.u32(header.argon2.iterations);
    writer.u32(header.argon2.lanes);
    writer.raw(header.salt);
  }
  return writer.take();
}

std::optional<ParsedHeader> decode_header(std::span<const unsigned char> file) {
  if (file.size() > kMostKeyringBytes) return std::nullopt;
  try {
    dannan::net::Reader reader(file);

    const auto magic = reader.view(kMagic.size());
    if (!std::equal(magic.begin(), magic.end(), kMagic.begin())) return std::nullopt;
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

    const auto id = reader.view(kKeyringIdBytes);
    parsed.header.id.assign(id.begin(), id.end());

    if (parsed.header.source == MasterKeySource::passphrase) {
      const auto memory = reader.u32();
      const auto iterations = reader.u32();
      const auto lanes = reader.u32();
      const auto salt = reader.view(kPassphraseSaltBytes);
      parsed.header.argon2 = crypto::Argon2Costs{memory, iterations, lanes};
      if (!parsed.header.argon2.valid()) return std::nullopt;
      parsed.header.salt.assign(salt.begin(), salt.end());
    }

    // The header is what was read; the sealed body follows it.
    parsed.length = file.size() - reader.remaining();
    return parsed;
  } catch (const dannan::net::DecodeError&) {
    return std::nullopt;
  }
}

SecureBuffer encode_body(const std::vector<DataKey>& keys) {
  SecureWriter writer;
  writer.u32(static_cast<std::uint32_t>(keys.size()));
  for (const auto& key : keys) {
    writer.u8(static_cast<std::uint8_t>(key.name.size()));
    writer.raw(byte_span(key.name));
    writer.u32(key.epoch);
    writer.u8(static_cast<std::uint8_t>(key.key.size()));
    writer.raw(key.key);
  }
  return writer.take();
}

std::optional<std::vector<DataKey>> decode_body(std::span<const unsigned char> body) {
  return decode_whole<std::vector<DataKey>>(body, [](dannan::net::Reader& reader) -> std::optional<std::vector<DataKey>> {
    const auto count = reader.u32();
    if (count > kMostDataKeys) return std::nullopt;

    std::vector<DataKey> keys;
    std::set<std::pair<std::string, std::uint32_t>> seen;
    for (std::uint32_t i = 0; i < count; ++i) {
      DataKey key;

      const auto name = reader.view(reader.u8());
      key.name.assign(name.begin(), name.end());
      if (!valid_key_name(key.name)) return std::nullopt;

      key.epoch = reader.u32();
      if (key.epoch == 0) return std::nullopt;

      if (reader.u8() != kDataKeyBytes) return std::nullopt;
      const auto material = reader.view(kDataKeyBytes);
      key.key.assign(material.begin(), material.end());

      if (!seen.emplace(key.name, key.epoch).second) return std::nullopt;
      keys.push_back(std::move(key));
    }
    return keys;
  });
}

}  // namespace lugh::keys

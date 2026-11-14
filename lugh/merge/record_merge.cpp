//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/merge/record_merge.h"

#include "lugh/core/codec.h"

namespace lugh::merge {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::uint8_t kLive = 0;
constexpr std::uint8_t kRemoved = 1;

}  // namespace

SecureBuffer encode(const Envelope& envelope) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.u64(envelope.version);
  writer.string(envelope.writer);
  writer.u8(envelope.removed ? kRemoved : kLive);
  writer.bytes(envelope.removed ? SecureBuffer{} : envelope.value);
  return writer.take();
}

std::optional<Envelope> decode(std::span<const unsigned char> bytes) {
  return decode_whole<Envelope>(bytes, [](dannan::net::Reader& reader) -> std::optional<Envelope> {
    if (reader.u8() != kFormat) return std::nullopt;
    Envelope out;
    out.version = reader.u64();
    out.writer = reader.string(kMostWriterBytes);
    const auto state = reader.u8();
    if (state != kLive && state != kRemoved) return std::nullopt;
    out.removed = state == kRemoved;
    const auto value = reader.view_bytes(kMostValueBytes);
    if (out.removed && !value.empty()) return std::nullopt;
    out.value = SecureBuffer(value.begin(), value.end());
    return out;
  });
}

const Envelope& winner(const Envelope& a, const Envelope& b) {
  if (a.removed != b.removed) return a.removed ? a : b;
  if (a.version != b.version) return a.version > b.version ? a : b;
  if (a.writer != b.writer) return a.writer > b.writer ? a : b;
  // The same version from the same writer: one write seen twice, or a writer that broke its own order. The larger value
  // decides, so even then every node agrees.
  return std::lexicographical_compare(a.value.begin(), a.value.end(), b.value.begin(), b.value.end()) ? b : a;
}

Records merge(const std::optional<Records>&, const std::vector<Records>& heads) {
  Records out;
  for (const auto& head : heads) {
    for (const auto& [key, envelope] : head) {
      const auto found = out.find(key);
      if (found == out.end()) {
        out.emplace(key, envelope);
      } else {
        found->second = winner(found->second, envelope);
      }
    }
  }
  return out;
}

bool writable(const Records& records, const std::string& key) {
  const auto found = records.find(key);
  return found == records.end() || !found->second.removed;
}

void UniqueIndex::add(const std::string& value, const std::string& key) { _keys[value].insert(key); }

void UniqueIndex::remove(const std::string& value, const std::string& key) {
  const auto found = _keys.find(value);
  if (found == _keys.end()) return;
  found->second.erase(key);
  if (found->second.empty()) _keys.erase(found);
}

UniqueIndex::Found UniqueIndex::find(const std::string& value) const {
  const auto found = _keys.find(value);
  if (found == _keys.end()) return {};
  if (found->second.size() > 1) return {std::nullopt, true};
  return {*found->second.begin(), false};
}

std::vector<std::string> UniqueIndex::ambiguous() const {
  std::vector<std::string> out;
  for (const auto& [value, keys] : _keys) {
    if (keys.size() > 1) out.push_back(value);
  }
  return out;
}

}  // namespace lugh::merge

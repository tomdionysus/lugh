//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/audit/audit_log.h"

#include <algorithm>
#include <cstdio>
#include <string_view>

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"

namespace lugh::audit {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::string_view kContext{"lugh audit v1\0", 14};

std::string cut(std::string text, std::size_t most) {
  if (text.size() > most) text.resize(most);
  return text;
}

// The entry without its hash, which is what the hash is over.
Bytes body(const Entry& entry) {
  dannan::net::Writer writer;
  writer.u8(kFormat);
  writer.u64(entry.sequence);
  writer.u64(entry.time);
  writer.string(entry.event.action);
  writer.string(entry.event.actor);
  writer.string(entry.event.subject);
  writer.string(entry.event.source);
  writer.string(entry.event.detail);
  writer.fixed(entry.previous);
  return writer.take();
}

Hash hash_of(std::span<const unsigned char> body) {
  Bytes input(kContext.begin(), kContext.end());
  input.insert(input.end(), body.begin(), body.end());
  return dannan::identity::sha256(input).bytes;
}

}  // namespace

AuditLog::AuditLog(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall)
    : _logger(std::move(log), "audit"), _store(std::move(store)), _wall(wall) {}

Task<Result<std::shared_ptr<AuditLog>>> AuditLog::open(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store,
                                                       const dannan::contract::WallClock& wall) {
  using Answer = Result<std::shared_ptr<AuditLog>>;
  std::shared_ptr<AuditLog> opened(new AuditLog(std::move(log), std::move(store), wall));

  // Keys are zero-padded, so the last in key order is the newest.
  const auto all = co_await opened->_store->list(kTable);
  if (!all.empty()) {
    const auto& last = all.back();
    const auto entry = decode(last.value);
    if (!entry || key(entry->sequence) != last.key) co_return Answer::failure("audit: entry " + last.key + " cannot be read");
    dannan::contract::Lock lock(opened->_mutex);
    opened->_next = entry->sequence + 1;
    opened->_last = entry->hash;
  }
  co_return Answer::success(std::move(opened));
}

Task<Status> AuditLog::record(Event event) {
  auto appending = co_await _appending.lock();

  Entry entry;
  {
    dannan::contract::Lock lock(_mutex);
    entry.sequence = _next;
    entry.previous = _last;
  }
  entry.time = (_wall.unix_ms() / 1000);
  entry.event.action = cut(std::move(event.action), kMostFieldBytes);
  entry.event.actor = cut(std::move(event.actor), kMostFieldBytes);
  entry.event.subject = cut(std::move(event.subject), kMostFieldBytes);
  entry.event.source = cut(std::move(event.source), kMostFieldBytes);
  entry.event.detail = cut(std::move(event.detail), kMostDetailBytes);
  entry.hash = hash_of(body(entry));

  const auto encoded = encode(entry);
  const auto written = co_await _store->put(kTable, key(entry.sequence), SecureBuffer(encoded.begin(), encoded.end()), 0);
  if (!written.ok()) {
    _logger.error("cannot record " + entry.event.action + " for " + entry.event.subject + ": " + written.message);
    co_return Status::failure("the audit log cannot be written: " + written.message);
  }

  dannan::contract::Lock lock(_mutex);
  _next = entry.sequence + 1;
  _last = entry.hash;
  co_return Status::success();
}

Task<std::vector<Entry>> AuditLog::entries(std::uint64_t from, std::size_t most) const {
  std::vector<Entry> out;
  for (auto sequence = std::max<std::uint64_t>(from, 1); out.size() < most; ++sequence) {
    const auto record = co_await _store->get(kTable, key(sequence));
    if (!record) break;
    auto entry = decode(record->value);
    if (!entry) break;
    out.push_back(std::move(*entry));
  }
  co_return out;
}

std::uint64_t AuditLog::size() const {
  dannan::contract::Lock lock(_mutex);
  return _next - 1;
}

Task<Result<std::uint64_t>> AuditLog::verify() const {
  using Answer = Result<std::uint64_t>;
  const auto count = size();

  Hash previous{};
  for (std::uint64_t sequence = 1; sequence <= count; ++sequence) {
    const auto record = co_await _store->get(kTable, key(sequence));
    if (!record) co_return Answer::failure("audit entry " + std::to_string(sequence) + " is missing");
    const auto entry = decode(record->value);
    if (!entry || entry->sequence != sequence) co_return Answer::failure("audit entry " + std::to_string(sequence) + " cannot be read");
    if (!dannan::identity::constant_time_equal(entry->previous, previous))
      co_return Answer::failure("audit entry " + std::to_string(sequence) + " does not follow the one before");
    if (!dannan::identity::constant_time_equal(entry->hash, hash_of(body(*entry))))
      co_return Answer::failure("audit entry " + std::to_string(sequence) + " has been altered");
    previous = entry->hash;
  }
  co_return Answer::success(count);
}

Bytes AuditLog::encode(const Entry& entry) {
  auto out = body(entry);
  out.insert(out.end(), entry.hash.begin(), entry.hash.end());
  return out;
}

std::optional<Entry> AuditLog::decode(std::span<const unsigned char> value) {
  return decode_whole<Entry>(value, [](dannan::net::Reader& reader) -> std::optional<Entry> {
    if (reader.u8() != kFormat) return std::nullopt;
    Entry entry;
    entry.sequence = reader.u64();
    entry.time = reader.u64();
    entry.event.action = reader.string(kMostFieldBytes);
    entry.event.actor = reader.string(kMostFieldBytes);
    entry.event.subject = reader.string(kMostFieldBytes);
    entry.event.source = reader.string(kMostFieldBytes);
    entry.event.detail = reader.string(kMostDetailBytes);
    entry.previous = reader.fixed<std::tuple_size_v<Hash>>();
    entry.hash = reader.fixed<std::tuple_size_v<Hash>>();
    return entry;
  });
}

std::string AuditLog::key(std::uint64_t sequence) {
  char buffer[24];
  std::snprintf(buffer, sizeof buffer, "%020llu", static_cast<unsigned long long>(sequence));
  return buffer;
}

}  // namespace lugh::audit

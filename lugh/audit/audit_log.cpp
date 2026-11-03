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

#include "lugh/core/byte_io.h"
#include "lugh/crypto/compare.h"
#include "lugh/loggers/logger_scoped.h"

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
  Bytes out;
  ByteWriter<Bytes> writer(out);
  writer.u8(kFormat);
  writer.u64(entry.sequence);
  writer.u64(entry.time);
  writer.field(entry.event.action);
  writer.field(entry.event.actor);
  writer.field(entry.event.subject);
  writer.field(entry.event.source);
  writer.field(entry.event.detail);
  writer.bytes(entry.previous);
  return out;
}

Hash hash_of(std::span<const unsigned char> body) {
  Bytes input(kContext.begin(), kContext.end());
  input.insert(input.end(), body.begin(), body.end());
  return crypto::sha256(input);
}

}  // namespace

AuditLog::AuditLog(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store, std::shared_ptr<system::Clock> clock)
    : _logger(std::make_shared<loggers::LoggerScoped>("audit", std::move(logger))), _store(std::move(store)), _clock(std::move(clock)) {}

Task<Result<std::shared_ptr<AuditLog>>> AuditLog::open(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store,
                                                       std::shared_ptr<system::Clock> clock) {
  using Answer = Result<std::shared_ptr<AuditLog>>;
  std::shared_ptr<AuditLog> log(new AuditLog(std::move(logger), std::move(store), std::move(clock)));

  // Keys are zero-padded, so the last in key order is the newest.
  const auto all = co_await log->_store->list(kTable);
  if (!all.empty()) {
    const auto& last = all.back();
    const auto entry = decode(last.value);
    if (!entry || key(entry->sequence) != last.key) co_return Answer::failure("audit: entry " + last.key + " cannot be read");
    log->_next = entry->sequence + 1;
    log->_last = entry->hash;
  }
  co_return Answer::success(std::move(log));
}

Task<Status> AuditLog::record(Event event) {
  auto appending = co_await _appending.lock();

  Entry entry;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    entry.sequence = _next;
    entry.previous = _last;
  }
  entry.time = system::unix_seconds(*_clock);
  entry.event.action = cut(std::move(event.action), kMostFieldBytes);
  entry.event.actor = cut(std::move(event.actor), kMostFieldBytes);
  entry.event.subject = cut(std::move(event.subject), kMostFieldBytes);
  entry.event.source = cut(std::move(event.source), kMostFieldBytes);
  entry.event.detail = cut(std::move(event.detail), kMostDetailBytes);
  entry.hash = hash_of(body(entry));

  const auto encoded = encode(entry);
  const auto written = co_await _store->put(kTable, key(entry.sequence), SecureBytes(encoded.begin(), encoded.end()), 0);
  if (!written.ok()) {
    _logger->error("cannot record " + entry.event.action + " for " + entry.event.subject + ": " + written.message);
    co_return Status::failure("the audit log cannot be written: " + written.message);
  }

  std::lock_guard<std::mutex> lock(_mutex);
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
  std::lock_guard<std::mutex> lock(_mutex);
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
    if (!crypto::equal(entry->previous, previous)) co_return Answer::failure("audit entry " + std::to_string(sequence) + " does not follow the one before");
    if (!crypto::equal(entry->hash, hash_of(body(*entry)))) co_return Answer::failure("audit entry " + std::to_string(sequence) + " has been altered");
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
  ByteReader reader(value);
  const auto format = reader.u8();
  if (!format || *format != kFormat) return std::nullopt;

  Entry entry;
  const auto sequence = reader.u64();
  const auto time = reader.u64();
  auto action = reader.field();
  auto actor = reader.field();
  auto subject = reader.field();
  auto source = reader.field();
  auto detail = reader.field();
  const auto previous = reader.bytes(entry.previous.size());
  const auto hash = reader.bytes(entry.hash.size());
  if (!sequence || !time || !action || !actor || !subject || !source || !detail || !previous || !hash || !reader.done()) return std::nullopt;

  entry.sequence = *sequence;
  entry.time = *time;
  entry.event = Event{std::move(*action), std::move(*actor), std::move(*subject), std::move(*source), std::move(*detail)};
  std::copy(previous->begin(), previous->end(), entry.previous.begin());
  std::copy(hash->begin(), hash->end(), entry.hash.begin());
  return entry;
}

std::string AuditLog::key(std::uint64_t sequence) {
  char buffer[24];
  std::snprintf(buffer, sizeof buffer, "%020llu", static_cast<unsigned long long>(sequence));
  return buffer;
}

}  // namespace lugh::audit

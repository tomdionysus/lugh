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
    : _logger(std::move(log), "audit"), _calls(std::move(store)), _wall(wall) {}

void AuditLog::open(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
                    Deadline deadline, Executor executor, Done<Result<std::shared_ptr<AuditLog>>> done) {
  using Answer = Result<std::shared_ptr<AuditLog>>;
  std::shared_ptr<AuditLog> opened(new AuditLog(std::move(log), std::move(store), wall));

  // Keys are zero-padded, so the last in key order is the newest.
  opened->_calls.list(kTable, deadline, executor, [opened, done = std::move(done)](Outcome<std::vector<store::Record>> all) {
    if (!all.ok()) return done(Answer::failure("audit: " + all.message));
    if (!all.value.empty()) {
      const auto& last = all.value.back();
      const auto entry = decode(last.value);
      if (!entry || key(entry->sequence) != last.key) return done(Answer::failure("audit: entry " + last.key + " cannot be read"));
      dannan::contract::Lock lock(opened->_mutex);
      opened->_next = entry->sequence + 1;
      opened->_last = entry->hash;
    }
    done(Answer::success(opened));
  });
}

void AuditLog::record(Event event, Deadline deadline, Executor executor, Done<Status> done) {
  auto completion = Completion<Status>::start(
      deadline, executor, std::move(done), [] { return Status::failure("the audit log did not answer within the deadline; the entry may yet be recorded"); });
  bool start = false;
  {
    dannan::contract::Lock lock(_mutex);
    _queue.push_back(Pending{std::move(event), std::move(completion), std::move(executor)});
    start = !_appending;
    _appending = true;
  }
  if (start) _append_next();
}

void AuditLog::_append_next() {
  Pending pending;
  Entry entry;
  {
    dannan::contract::Lock lock(_mutex);
    if (_queue.empty()) {
      _appending = false;
      return;
    }
    pending = std::move(_queue.front());
    _queue.pop_front();
    entry.sequence = _next;
    entry.previous = _last;
  }
  entry.time = (_wall.unix_ms() / 1000);
  entry.event.action = cut(std::move(pending.event.action), kMostFieldBytes);
  entry.event.actor = cut(std::move(pending.event.actor), kMostFieldBytes);
  entry.event.subject = cut(std::move(pending.event.subject), kMostFieldBytes);
  entry.event.source = cut(std::move(pending.event.source), kMostFieldBytes);
  entry.event.detail = cut(std::move(pending.event.detail), kMostDetailBytes);
  entry.hash = hash_of(body(entry));

  const auto encoded = encode(entry);
  // The write's own answer, however long it takes: the next entry is numbered from it.
  _calls.put_settled(kTable, key(entry.sequence), SecureBuffer(encoded.begin(), encoded.end()), 0, pending.executor,
                     [self = shared_from_this(), entry, completion = pending.completion](store::Write written) {
                       if (!written.ok()) {
                         self->_logger.error("cannot record " + entry.event.action + " for " + entry.event.subject + ": " + written.message);
                         completion->finish(Status::failure("the audit log cannot be written: " + written.message));
                       } else {
                         {
                           dannan::contract::Lock lock(self->_mutex);
                           self->_next = entry.sequence + 1;
                           self->_last = entry.hash;
                         }
                         completion->finish(Status::success());
                       }
                       self->_append_next();
                     });
}

struct AuditLog::Walk {
  // The entries walk's answer, or the verify walk's.
  std::shared_ptr<Completion<Outcome<std::vector<Entry>>>> page;
  std::shared_ptr<Completion<Result<std::uint64_t>>> verdict;
  Executor executor;
  std::uint64_t sequence = 1;
  std::size_t most = 0;
  std::vector<Entry> out;
  // verify(): how far to go, and the hash the next entry must follow.
  std::uint64_t count = 0;
  Hash previous{};
};

void AuditLog::entries(std::uint64_t from, std::size_t most, Deadline deadline, Executor executor, Done<Outcome<std::vector<Entry>>> done) const {
  auto walk = std::make_shared<Walk>();
  walk->page = Completion<Outcome<std::vector<Entry>>>::start(deadline, executor, std::move(done), [] {
    return Outcome<std::vector<Entry>>::failure(Fault::failed, "the audit log was not read within the deadline");
  });
  walk->executor = std::move(executor);
  walk->sequence = std::max<std::uint64_t>(from, 1);
  walk->most = most;
  _walk_entries(std::move(walk));
}

void AuditLog::_walk_entries(std::shared_ptr<Walk> walk) const {
  using Answer = Outcome<std::vector<Entry>>;
  if (walk->page->answered()) return;
  if (walk->out.size() >= walk->most) return walk->page->finish(Answer::success(std::move(walk->out)));
  _calls.get_settled(kTable, key(walk->sequence), walk->executor, [self = shared_from_this(), walk](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return walk->page->finish(Answer::failure(record.fault, record.message));
    // The chain ends where a record is missing or unreadable.
    const auto entry = record.value ? decode(record.value->value) : std::nullopt;
    if (!entry) return walk->page->finish(Answer::success(std::move(walk->out)));
    walk->out.push_back(std::move(*entry));
    ++walk->sequence;
    self->_walk_entries(walk);
  });
}

void AuditLog::abandon_pending() {
  std::deque<Pending> dropped;
  {
    dannan::contract::Lock state(_mutex);
    dropped.swap(_queue);
    _appending = false;
  }
}

std::uint64_t AuditLog::size() const {
  dannan::contract::Lock lock(_mutex);
  return _next - 1;
}

void AuditLog::verify(Deadline deadline, Executor executor, Done<Result<std::uint64_t>> done) const {
  auto walk = std::make_shared<Walk>();
  walk->verdict = Completion<Result<std::uint64_t>>::start(deadline, executor, std::move(done),
                                                           [] { return Result<std::uint64_t>::failure("the audit chain was not walked within the deadline"); });
  walk->executor = std::move(executor);
  walk->count = size();
  _walk_verify(std::move(walk));
}

void AuditLog::_walk_verify(std::shared_ptr<Walk> walk) const {
  using Answer = Result<std::uint64_t>;
  if (walk->verdict->answered()) return;
  if (walk->sequence > walk->count) return walk->verdict->finish(Answer::success(walk->count));
  _calls.get_settled(kTable, key(walk->sequence), walk->executor, [self = shared_from_this(), walk](Outcome<std::optional<store::Record>> record) {
    const auto sequence = std::to_string(walk->sequence);
    if (!record.ok()) return walk->verdict->finish(Answer::failure("audit entry " + sequence + ": " + record.message));
    if (!record.value) return walk->verdict->finish(Answer::failure("audit entry " + sequence + " is missing"));
    const auto entry = decode(record.value->value);
    if (!entry || entry->sequence != walk->sequence) return walk->verdict->finish(Answer::failure("audit entry " + sequence + " cannot be read"));
    if (!dannan::identity::constant_time_equal(entry->previous, walk->previous))
      return walk->verdict->finish(Answer::failure("audit entry " + sequence + " does not follow the one before"));
    if (!dannan::identity::constant_time_equal(entry->hash, hash_of(body(*entry))))
      return walk->verdict->finish(Answer::failure("audit entry " + sequence + " has been altered"));
    walk->previous = entry->hash;
    ++walk->sequence;
    self->_walk_verify(walk);
  });
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

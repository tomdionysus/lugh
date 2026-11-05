//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/directory/posix_numbers.h"

#include "lugh/core/codec.h"

namespace lugh::directory {

namespace {

constexpr const char* kUserCounter = "posix.uid";
constexpr const char* kGroupCounter = "posix.gid";
// Many creations at once each lose at most to the others, so this is generous.
constexpr int kTries = 64;

SecureBuffer encode(std::uint32_t next) {
  SecureWriter writer;
  writer.u32(next);
  return writer.take();
}

std::optional<std::uint32_t> decode(std::span<const unsigned char> value) {
  return decode_whole<std::uint32_t>(value, [](dannan::net::Reader& reader) -> std::optional<std::uint32_t> { return reader.u32(); });
}

}  // namespace

PosixNumbers::PosixNumbers(std::shared_ptr<store::Store> store, Range users, Range groups) : _calls(std::move(store)), _users(users), _groups(groups) {}

void PosixNumbers::next_user(Executor executor, Done<Outcome<std::uint32_t>> done) {
  _next(kUserCounter, _users, kTries, std::move(executor), std::move(done));
}

void PosixNumbers::next_group(Executor executor, Done<Outcome<std::uint32_t>> done) {
  _next(kGroupCounter, _groups, kTries, std::move(executor), std::move(done));
}

void PosixNumbers::_next(std::string key, Range range, int tries, Executor executor, Done<Outcome<std::uint32_t>> done) {
  using Answer = Outcome<std::uint32_t>;
  auto self = shared_from_this();
  _calls.get_settled(kTable, key, executor, [=](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    std::uint32_t number = range.first;
    std::uint64_t expected = 0;
    if (record.value) {
      const auto stored = decode(record.value->value);
      if (!stored) return done(Answer::failure(Fault::failed, "the counter " + key + " does not decode"));
      // A range moved up since is honoured; moved down, nothing given out is given again.
      number = std::max(*stored, range.first);
      expected = record.value->version;
    }
    if (number > range.last) return done(Answer::failure(Fault::refused, "the POSIX numbers in the configured range are used up"));
    // Past the last, kept as one past it, so a wider range later goes on from there.
    self->_calls.put_settled(kTable, key, encode(number + 1), expected, executor, [=](store::Write written) {
      if (written.ok()) return done(Answer::success(number));
      if (written.error == store::StoreError::conflict && tries > 1) return self->_next(key, range, tries - 1, executor, done);
      done(Answer::failure(Fault::failed, written.message));
    });
  });
}

}  // namespace lugh::directory

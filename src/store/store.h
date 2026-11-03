//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/secure_bytes.h"
#include "core/task.h"

namespace lugh::store {

// One record: its key, its version, and its value, opened.
struct Record {
  std::string key;
  std::uint64_t version = 0;
  SecureBytes value;
};

// A secondary index: the values a record is found by (a user name, an email), from the
// record's value. Derived, never stored: rebuilt from the table at every open. Unique: two
// live records cannot share an index value.
struct IndexSpec {
  std::string name;
  std::function<std::vector<std::string>(std::span<const unsigned char> value)> keys;
};

struct TableSpec {
  std::string name;
  std::vector<IndexSpec> indexes;
};

// Why a write was refused. The codes are vocabulary for the API, as its error codes are.
enum class StoreError {
  none,
  // No such table, or (for a remove) no such record.
  not_found,
  // The record is not at the version the caller expected.
  conflict,
  // The record was removed, and a removal is final: a key is never used again.
  removed,
  // A unique index already has the value for another record.
  duplicate,
  // A key or value out of bounds.
  invalid,
  // The disk, the keys or the randomness failed; the record is as it was.
  failed,
};

struct Write {
  StoreError error = StoreError::none;
  std::string message;
  // The record's version after the write.
  std::uint64_t version = 0;

  bool ok() const { return error == StoreError::none; }

  static Write success(std::uint64_t version) { return Write{StoreError::none, {}, version}; }
  static Write failure(StoreError error, std::string message) { return Write{error, std::move(message), 0}; }
};

// The tables. A put creates a record at version 1 or moves it to the next version; a
// remove leaves a tombstone at the next version, and the key can never be put again. The
// expected version, when given, makes the write conditional: 0 means "must not exist", any
// other value "must be at exactly this version".
//
// Every operation is awaited, and none holds a thread while it waits: a write suspends while
// its frame reaches the disk, and a writer behind it on the same table suspends on the
// table's lock. Arguments are owned, because the caller's need not outlive a suspension.
// Safe from any number of coroutines on any number of threads.
class Store {
 public:
  virtual ~Store() = default;

  // nullopt for a key that is absent or removed, or a table that is not.
  virtual Task<std::optional<Record>> get(std::string table, std::string key) const = 0;

  // The record a unique index value points at.
  virtual Task<std::optional<Record>> find(std::string table, std::string index, std::string value) const = 0;

  // Every live record, in key order.
  virtual Task<std::vector<Record>> list(std::string table) const = 0;

  // Whether the key has been removed: the tombstones are kept for ever.
  virtual Task<bool> removed(std::string table, std::string key) const = 0;

  // The value is SecureBytes: what a record holds may be a secret until it is sealed.
  virtual Task<Write> put(std::string table, std::string key, SecureBytes value, std::optional<std::uint64_t> expected = std::nullopt) = 0;

  virtual Task<Write> remove(std::string table, std::string key, std::optional<std::uint64_t> expected = std::nullopt) = 0;
};

}  // namespace lugh::store

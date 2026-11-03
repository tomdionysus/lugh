//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <map>
#include <mutex>
#include <set>

#include "lugh/store/log_format.h"
#include "lugh/store/store.h"

// The store's rules, in memory and nowhere else: versions, final removals, conditional
// writes and unique indexes, as SealedStore keeps them. The contract tests run against
// both (lugh/test/store_contract_test.cpp). Every answer is ready at once.
class MemoryStore : public lugh::store::Store {
 public:
  explicit MemoryStore(std::vector<lugh::store::TableSpec> tables) {
    for (auto& spec : tables) _tables[spec.name].spec = std::move(spec);
  }

  lugh::Task<std::optional<lugh::store::Record>> get(std::string table, std::string key) const override { co_return get_now(table, key); }

  lugh::Task<std::optional<lugh::store::Record>> find(std::string table, std::string index, std::string value) const override {
    std::string key;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      const auto t = _tables.find(table);
      if (t == _tables.end()) co_return std::nullopt;
      const auto by_index = t->second.indexes.find(index);
      if (by_index == t->second.indexes.end()) co_return std::nullopt;
      const auto hit = by_index->second.find(value);
      if (hit == by_index->second.end()) co_return std::nullopt;
      key = hit->second;
    }
    co_return get_now(table, key);
  }

  lugh::Task<std::vector<lugh::store::Record>> list(std::string table) const override { co_return list_now(table); }

  lugh::Task<bool> removed(std::string table, std::string key) const override {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto* found = _entry(table, key);
    co_return found != nullptr && found->removed;
  }

  lugh::Task<lugh::store::Write> put(std::string table, std::string key, lugh::SecureBytes value,
                                     std::optional<std::uint64_t> expected = std::nullopt) override {
    co_return put_now(table, key, value, expected);
  }

  lugh::Task<lugh::store::Write> remove(std::string table, std::string key, std::optional<std::uint64_t> expected = std::nullopt) override {
    co_return _write(table, true, key, {}, expected);
  }

  // For the test itself, which is not a coroutine: the same, answered directly.
  std::optional<lugh::store::Record> get_now(std::string_view table, std::string_view key) const {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto* found = _entry(table, key);
    if (found == nullptr || found->removed) return std::nullopt;
    return lugh::store::Record{std::string(key), found->version, found->value};
  }

  std::vector<lugh::store::Record> list_now(std::string_view table) const {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<lugh::store::Record> out;
    const auto t = _tables.find(table);
    if (t == _tables.end()) return out;
    for (const auto& [key, entry] : t->second.entries) {
      if (!entry.removed) out.push_back(lugh::store::Record{key, entry.version, entry.value});
    }
    return out;
  }

  lugh::store::Write put_now(std::string_view table, std::string_view key, std::span<const unsigned char> value,
                             std::optional<std::uint64_t> expected = std::nullopt) {
    return _write(table, false, key, value, expected);
  }

  lugh::store::Write remove_now(std::string_view table, std::string_view key) { return _write(table, true, key, {}, std::nullopt); }

 private:
  struct Entry {
    std::uint64_t version = 0;
    bool removed = false;
    lugh::SecureBytes value;
    std::map<std::string, std::set<std::string>> index_values;
  };

  struct Table {
    lugh::store::TableSpec spec;
    std::map<std::string, Entry, std::less<>> entries;
    std::map<std::string, std::map<std::string, std::string, std::less<>>, std::less<>> indexes;
  };

  const Entry* _entry(std::string_view table, std::string_view key) const {
    const auto t = _tables.find(table);
    if (t == _tables.end()) return nullptr;
    const auto e = t->second.entries.find(key);
    return e == t->second.entries.end() ? nullptr : &e->second;
  }

  lugh::store::Write _write(std::string_view name, bool remove, std::string_view key, std::span<const unsigned char> value,
                            std::optional<std::uint64_t> expected) {
    using lugh::store::StoreError;
    using lugh::store::Write;
    std::lock_guard<std::mutex> lock(_mutex);

    const auto t = _tables.find(name);
    if (t == _tables.end()) return Write::failure(StoreError::not_found, "no table");
    auto& table = t->second;
    if (key.empty() || key.size() > lugh::store::kMostKeyBytes) return Write::failure(StoreError::invalid, "bad key");
    if (value.size() > lugh::store::kMostValueBytes) return Write::failure(StoreError::invalid, "bad value");

    const auto found = table.entries.find(key);
    const bool exists = found != table.entries.end();
    if (exists && found->second.removed) return Write::failure(StoreError::removed, "removed");
    const std::uint64_t current = exists ? found->second.version : 0;
    if (expected && *expected != current) return Write::failure(StoreError::conflict, "conflict");
    if (remove && !exists) return Write::failure(StoreError::not_found, "no record");

    std::map<std::string, std::set<std::string>> values;
    if (!remove) {
      for (const auto& index : table.spec.indexes) {
        const auto keys = index.keys(value);
        values[index.name] = std::set<std::string>(keys.begin(), keys.end());
        for (const auto& one : values[index.name]) {
          const auto taken = table.indexes[index.name].find(one);
          if (taken != table.indexes[index.name].end() && taken->second != key) return Write::failure(StoreError::duplicate, "duplicate");
        }
      }
    }

    if (exists) {
      for (const auto& [index, list] : found->second.index_values) {
        for (const auto& one : list) table.indexes[index].erase(one);
      }
    }
    for (const auto& [index, list] : values) {
      for (const auto& one : list) table.indexes[index][one] = std::string(key);
    }

    Entry entry;
    entry.version = current + 1;
    entry.removed = remove;
    entry.value.assign(value.begin(), value.end());
    entry.index_values = std::move(values);
    table.entries.insert_or_assign(std::string(key), std::move(entry));
    return Write::success(current + 1);
  }

  mutable std::mutex _mutex;
  std::map<std::string, Table, std::less<>> _tables;
};

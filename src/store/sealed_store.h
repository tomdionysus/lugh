//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "core/async_mutex.h"
#include "core/status.h"
#include "core/task.h"
#include "keys/keyring.h"
#include "keys/keyring_manager.h"
#include "loggers/logger.h"
#include "store/log_format.h"
#include "store/store.h"
#include "system/files.h"
#include "system/random.h"

namespace lugh::store {

// The store on disk: one sealed log per table under the store directory
// (<state>/store/<table>.log), and in memory each record's sealed frame, opened again on
// every read, so a record's plaintext lives only as long as the caller holds it. The
// indexes are in memory, rebuilt at open.
//
// Every write is appended and synced before it is acknowledged. A write that fails part
// way is cut back off the file; if that fails too, the table refuses writes until the
// next open, which cuts it there. A torn tail found at open is cut off and logged. Damage
// in the middle of a log stops the open: a dropped frame might be a revocation, and Lugh
// never runs on a table it cannot read whole.
//
// Compaction rewrites a table's live records and tombstones, sealed again under its
// current data key, into a new file that replaces the old in one rename. It runs when a
// table is more than half superseded, and after a rotation.
//
// Each table has two locks. Its write lock is an AsyncMutex, held by one writer (or a
// compaction, or a rotation) from validation through the synced append to the change in
// memory, so writers on a table go one at a time and a waiting one holds no thread. Its
// state lock is a std::mutex, held only for moments in which nothing is awaited: a read
// takes it to find and open a record, a writer to check and then to apply. A read never
// waits for a write's disk.
class SealedStore : public Store {
 public:
  // Compaction runs once a log is past this and more than half superseded.
  static constexpr std::size_t kCompactAfterBytes = 1024 * 1024;

  static Task<Result<std::shared_ptr<SealedStore>>> open(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<system::Files> files,
                                                         std::shared_ptr<system::Random> random, std::shared_ptr<keys::KeyringManager> keyrings,
                                                         keys::Keyring keyring, std::string directory, std::vector<TableSpec> tables);

  Task<std::optional<Record>> get(std::string table, std::string key) const override;
  Task<std::optional<Record>> find(std::string table, std::string index, std::string value) const override;
  Task<std::vector<Record>> list(std::string table) const override;
  Task<bool> removed(std::string table, std::string key) const override;
  // The defaults are the interface's, repeated: a call through a SealedStore does not see
  // the base class's.
  Task<Write> put(std::string table, std::string key, SecureBytes value, std::optional<std::uint64_t> expected = std::nullopt) override;
  Task<Write> remove(std::string table, std::string key, std::optional<std::uint64_t> expected = std::nullopt) override;

  // Rewrites the table now.
  Task<Status> compact(std::string table);

  // A new data key epoch for the table, saved to the keyring, then the table compacted
  // under it, so nothing is left sealed under the old.
  Task<Status> rotate(std::string table);

  // The table's log: its length, and how much of it is superseded.
  struct Usage {
    std::size_t bytes = 0;
    std::size_t superseded = 0;
    std::uint32_t epoch = 0;
  };
  std::optional<Usage> usage(std::string_view table) const;

 private:
  struct Entry {
    std::uint64_t version = 0;
    bool removed = false;
    SealedFrame frame;
    // The index values it holds, by index name.
    std::map<std::string, std::vector<std::string>> index_values;
  };

  struct Table {
    TableSpec spec;
    std::string path;

    AsyncMutex write_lock;
    mutable std::mutex mutex;
    std::map<std::string, Entry, std::less<>> entries;
    // index name -> value -> key
    std::map<std::string, std::map<std::string, std::string, std::less<>>, std::less<>> indexes;
    std::map<std::uint32_t, SecureBytes> keys;
    std::uint32_t epoch = 0;
    Bytes last_tag;
    std::size_t length = 0;
    std::size_t superseded = 0;
    bool broken = false;
  };

  SealedStore(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<system::Files> files, std::shared_ptr<system::Random> random,
              std::shared_ptr<keys::KeyringManager> keyrings, keys::Keyring keyring, std::string directory);

  Task<Status> _open_table(TableSpec spec);
  Task<Status> _load_keys(Table& table);
  Status _apply(Table& table, Scan::Entry entry);
  Task<Write> _write(Table& table, Operation operation, std::string key, SecureBytes value, std::optional<std::uint64_t> expected);
  // With the table's write lock held.
  Task<Status> _compact(Table& table);
  std::optional<Record> _open_entry(const Table& table, const std::string& key, const Entry& entry) const;
  Table* _table(std::string_view name) const;

  std::shared_ptr<loggers::Logger> _logger;
  std::shared_ptr<system::Files> _files;
  std::shared_ptr<system::Random> _random;
  std::shared_ptr<keys::KeyringManager> _keyrings;
  std::string _directory;

  // The keyring changes only on a rotation, under its own lock, which is taken after a
  // table's write lock and never before. Async: it is held while the keyring is saved.
  AsyncMutex _keyring_lock;
  keys::Keyring _keyring;

  // Fixed once open() returns.
  std::map<std::string, std::unique_ptr<Table>, std::less<>> _tables;
};

}  // namespace lugh::store

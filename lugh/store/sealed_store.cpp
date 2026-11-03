//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/store/sealed_store.h"

#include <set>
#include <utility>

#include "lugh/loggers/logger_scoped.h"

namespace lugh::store {

namespace {

Status refuse(const std::string& path, const std::string& why) { return Status::failure(path + ": " + why); }

// The index values a record holds, each index's sorted and without repeats.
std::map<std::string, std::vector<std::string>> index_values(const TableSpec& spec, std::span<const unsigned char> value) {
  std::map<std::string, std::vector<std::string>> out;
  for (const auto& index : spec.indexes) {
    auto keys = index.keys(value);
    std::set<std::string> unique(keys.begin(), keys.end());
    out[index.name] = std::vector<std::string>(unique.begin(), unique.end());
  }
  return out;
}

}  // namespace

SealedStore::SealedStore(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<system::Files> files, std::shared_ptr<system::Random> random,
                         std::shared_ptr<keys::KeyringManager> keyrings, keys::Keyring keyring, std::string directory)
    : _logger(std::make_shared<loggers::LoggerScoped>("store", std::move(logger))),
      _files(std::move(files)),
      _random(std::move(random)),
      _keyrings(std::move(keyrings)),
      _directory(std::move(directory)),
      _keyring(std::move(keyring)) {}

Task<Result<std::shared_ptr<SealedStore>>> SealedStore::open(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<system::Files> files,
                                                             std::shared_ptr<system::Random> random, std::shared_ptr<keys::KeyringManager> keyrings,
                                                             keys::Keyring keyring, std::string directory, std::vector<TableSpec> tables) {
  using Answer = Result<std::shared_ptr<SealedStore>>;

  std::shared_ptr<SealedStore> store(
      new SealedStore(std::move(logger), std::move(files), std::move(random), std::move(keyrings), std::move(keyring), std::move(directory)));

  if (const auto made = co_await store->_files->make_directory(store->_directory); !made.ok) co_return Answer::failure(made.error);

  for (auto& spec : tables) {
    if (!keys::valid_key_name(spec.name)) co_return Answer::failure("a table's name is 1 to 64 of a-z, 0-9 and _: " + spec.name);
    if (store->_tables.count(spec.name) != 0) co_return Answer::failure("table " + spec.name + " is named twice");
    if (const auto opened = co_await store->_open_table(std::move(spec)); !opened.ok) co_return Answer::failure(opened.error);
  }

  store->_logger->info("Opened " + std::to_string(store->_tables.size()) + " tables in " + store->_directory);
  co_return Answer::success(std::move(store));
}

Task<Status> SealedStore::_load_keys(Table& table) {
  auto held = co_await _keyring_lock.lock();
  const auto& name = table.spec.name;

  if (_keyring.current(name) == nullptr) {
    if (const auto made = _keyring.rotate(name, *_random); !made.ok) co_return Status::failure(made.error);
    if (const auto saved = co_await _keyrings->save(_keyring); !saved.ok) co_return saved;
    _logger->info("Made the first data key for table " + name);
  }

  const auto* current = _keyring.current(name);
  for (std::uint32_t epoch = 1; epoch <= current->epoch; ++epoch) {
    if (const auto* key = _keyring.find(name, epoch)) table.keys[epoch] = key->key;
  }
  table.epoch = current->epoch;
  co_return Status::success();
}

// Before open() returns, so nothing else can see the table yet and its locks are not needed.
Task<Status> SealedStore::_open_table(TableSpec spec) {
  auto table = std::make_unique<Table>();
  table->spec = std::move(spec);
  table->path = _directory + "/" + table->spec.name + ".log";
  const auto path = table->path;

  if (const auto loaded = co_await _load_keys(*table); !loaded.ok) co_return refuse(path, loaded.error);

  if (!co_await _files->exists(path)) {
    const auto header = make_file_header(table->spec.name, table->epoch, table->keys.at(table->epoch), *_random);
    if (!header.ok) co_return refuse(path, header.error);
    if (const auto written = co_await _files->write(path, encode_file_header(header.value), false); !written.ok) co_return written;
  }

  const auto file = co_await _files->read(path, kMostTableFileBytes);
  if (!file.ok) co_return Status::failure(file.error);

  const KeyFor key_for = [&table](std::uint32_t epoch) -> const SecureBuffer* {
    const auto found = table->keys.find(epoch);
    return found == table->keys.end() ? nullptr : &found->second;
  };
  auto scan = scan_log(file.value, table->spec.name, key_for);
  if (!scan.ok) co_return refuse(path, scan.error);

  if (scan.value.end == Scan::End::damaged) {
    co_return refuse(path, "damaged at byte " + std::to_string(scan.value.problem_offset) + " (" + scan.value.problem +
                               ") with records after it; Lugh will not run on part of a table. Restore it from another node or a backup");
  }

  table->last_tag = scan.value.header.tag();
  for (auto& entry : scan.value.entries) {
    if (const auto applied = _apply(*table, std::move(entry)); !applied.ok) co_return refuse(path, applied.error);
  }
  table->length = scan.value.valid_length;

  if (scan.value.end == Scan::End::torn) {
    _logger->warn(path + ": cut a torn tail at byte " + std::to_string(scan.value.problem_offset) + " (" + scan.value.problem + ", " +
                  std::to_string(file.value.size() - scan.value.valid_length) + " bytes); nothing there had been acknowledged");
    if (const auto cut = co_await _files->truncate(path, scan.value.valid_length); !cut.ok) co_return cut;
  }

  _tables.emplace(table->spec.name, std::move(table));
  co_return Status::success();
}

// One frame read at open, applied in order. A log Lugh wrote never breaks these rules, so
// one that does was not written by Lugh.
Status SealedStore::_apply(Table& table, Scan::Entry scanned) {
  auto& change = scanned.change;
  const auto found = table.entries.find(change.key);

  if (found != table.entries.end()) {
    if (found->second.removed) return Status::failure("a record for " + change.key + " after its removal");
    if (change.version <= found->second.version) return Status::failure("record " + change.key + " goes back a version");
  }

  Entry entry;
  entry.version = change.version;
  entry.removed = change.operation == Operation::remove;
  if (!entry.removed) entry.index_values = index_values(table.spec, change.value);

  if (found != table.entries.end()) {
    table.superseded += found->second.frame.size();
    for (const auto& [index, values] : found->second.index_values) {
      for (const auto& value : values) table.indexes[index].erase(value);
    }
  }

  for (const auto& [index, values] : entry.index_values) {
    for (const auto& value : values) {
      const auto [where, added] = table.indexes[index].emplace(value, change.key);
      if (!added && where->second != change.key) return Status::failure("index " + index + " holds a value twice");
    }
  }

  table.last_tag = scanned.frame.tag();
  entry.frame = std::move(scanned.frame);
  table.entries[change.key] = std::move(entry);
  return Status::success();
}

SealedStore::Table* SealedStore::_table(std::string_view name) const {
  const auto found = _tables.find(name);
  return found == _tables.end() ? nullptr : found->second.get();
}

std::optional<Record> SealedStore::_open_entry(const Table& table, const std::string& key, const Entry& entry) const {
  const auto data_key = table.keys.find(entry.frame.epoch);
  if (data_key == table.keys.end()) return std::nullopt;

  auto change = open_frame(entry.frame, table.spec.name, data_key->second);
  if (!change || change->key != key || change->version != entry.version) {
    _logger->error(table.path + ": record " + key + " does not open in memory");
    return std::nullopt;
  }
  return Record{key, entry.version, std::move(change->value)};
}

// Reads answer from memory under the state lock and never suspend.

Task<std::optional<Record>> SealedStore::get(std::string name, std::string key) const {
  const auto* table = _table(name);
  if (table == nullptr) co_return std::nullopt;

  std::lock_guard<std::mutex> lock(table->mutex);
  const auto found = table->entries.find(key);
  if (found == table->entries.end() || found->second.removed) co_return std::nullopt;
  co_return _open_entry(*table, found->first, found->second);
}

Task<std::optional<Record>> SealedStore::find(std::string name, std::string index, std::string value) const {
  const auto* table = _table(name);
  if (table == nullptr) co_return std::nullopt;

  std::lock_guard<std::mutex> lock(table->mutex);
  const auto by_index = table->indexes.find(index);
  if (by_index == table->indexes.end()) co_return std::nullopt;
  const auto key = by_index->second.find(value);
  if (key == by_index->second.end()) co_return std::nullopt;
  const auto found = table->entries.find(key->second);
  if (found == table->entries.end() || found->second.removed) co_return std::nullopt;
  co_return _open_entry(*table, found->first, found->second);
}

Task<std::vector<Record>> SealedStore::list(std::string name) const {
  std::vector<Record> out;
  const auto* table = _table(name);
  if (table == nullptr) co_return out;

  std::lock_guard<std::mutex> lock(table->mutex);
  for (const auto& [key, entry] : table->entries) {
    if (entry.removed) continue;
    if (auto record = _open_entry(*table, key, entry)) out.push_back(std::move(*record));
  }
  co_return out;
}

Task<bool> SealedStore::removed(std::string name, std::string key) const {
  const auto* table = _table(name);
  if (table == nullptr) co_return false;

  std::lock_guard<std::mutex> lock(table->mutex);
  const auto found = table->entries.find(key);
  co_return found != table->entries.end() && found->second.removed;
}

Task<Write> SealedStore::put(std::string name, std::string key, SecureBuffer value, std::optional<std::uint64_t> expected) {
  auto* table = _table(name);
  if (table == nullptr) co_return Write::failure(StoreError::not_found, "no table " + name);
  co_return co_await _write(*table, Operation::put, std::move(key), std::move(value), expected);
}

Task<Write> SealedStore::remove(std::string name, std::string key, std::optional<std::uint64_t> expected) {
  auto* table = _table(name);
  if (table == nullptr) co_return Write::failure(StoreError::not_found, "no table " + name);
  co_return co_await _write(*table, Operation::remove, std::move(key), {}, expected);
}

Task<Write> SealedStore::_write(Table& table, Operation operation, std::string key, SecureBuffer value, std::optional<std::uint64_t> expected) {
  // One writer at a time on this table, from the check to the change in memory, so what is
  // checked is still true when it is applied. Readers carry on meanwhile.
  auto writing = co_await table.write_lock.lock();
  const auto& name = table.spec.name;

  // Checked and sealed under the state lock, which is not held while the disk works.
  std::uint64_t version = 0;
  std::map<std::string, std::vector<std::string>> values;
  SealedFrame frame;
  Bytes bytes;
  std::size_t length = 0;
  {
    std::lock_guard<std::mutex> lock(table.mutex);
    if (table.broken) co_return Write::failure(StoreError::failed, "table " + name + " refuses writes after one failed part way; restart Lugh");
    if (key.empty() || key.size() > kMostKeyBytes) co_return Write::failure(StoreError::invalid, "a key is 1 to 255 bytes");
    if (value.size() > kMostValueBytes) co_return Write::failure(StoreError::invalid, "a value is at most 256 KiB");

    const auto found = table.entries.find(key);
    const bool exists = found != table.entries.end();
    if (exists && found->second.removed) co_return Write::failure(StoreError::removed, "record " + key + " was removed");

    const std::uint64_t current = exists ? found->second.version : 0;
    if (expected && *expected != current) {
      co_return Write::failure(StoreError::conflict, "record " + key + " is at version " + std::to_string(current) + ", not " + std::to_string(*expected));
    }
    if (operation == Operation::remove && !exists) co_return Write::failure(StoreError::not_found, "no record " + key);

    if (operation == Operation::put) {
      values = index_values(table.spec, value);
      for (const auto& [index, list] : values) {
        const auto by_value = table.indexes.find(index);
        if (by_value == table.indexes.end()) continue;
        for (const auto& one : list) {
          const auto taken = by_value->second.find(one);
          if (taken != by_value->second.end() && taken->second != key) {
            co_return Write::failure(StoreError::duplicate, "index " + index + " of table " + name + " already has that value");
          }
        }
      }
    }

    Change change;
    change.operation = operation;
    change.version = version = current + 1;
    change.key = key;
    change.value = std::move(value);

    auto framed = seal_change(change, name, table.epoch, table.keys.at(table.epoch), table.last_tag);
    if (!framed.ok) co_return Write::failure(StoreError::failed, framed.error);
    frame = std::move(framed.value.frame);
    bytes = std::move(framed.value.bytes);
    length = table.length;
  }

  if (const auto appended = co_await _files->append(table.path, std::move(bytes)); !appended.ok) {
    if (const auto cut = co_await _files->truncate(table.path, length); !cut.ok) {
      std::lock_guard<std::mutex> lock(table.mutex);
      table.broken = true;
      _logger->error(table.path + ": a write failed part way and could not be cut back (" + cut.error + "); the table refuses writes until restart");
    }
    co_return Write::failure(StoreError::failed, appended.error);
  }

  // Durable: now memory follows.
  bool compact = false;
  {
    std::lock_guard<std::mutex> lock(table.mutex);
    const auto found = table.entries.find(key);
    if (found != table.entries.end()) {
      table.superseded += found->second.frame.size();
      for (const auto& [index, list] : found->second.index_values) {
        for (const auto& one : list) table.indexes[index].erase(one);
      }
    }
    for (const auto& [index, list] : values) {
      for (const auto& one : list) table.indexes[index][one] = key;
    }

    Entry entry;
    entry.version = version;
    entry.removed = operation == Operation::remove;
    entry.index_values = std::move(values);
    entry.frame = std::move(frame);
    table.last_tag = entry.frame.tag();
    table.length += entry.frame.size();
    table.entries.insert_or_assign(key, std::move(entry));
    compact = table.length > kCompactAfterBytes && table.superseded * 2 > table.length;
  }

  if (compact) {
    if (const auto compacted = co_await _compact(table); !compacted.ok) _logger->warn(table.path + ": compaction failed: " + compacted.error);
  }
  co_return Write::success(version);
}

Task<Status> SealedStore::compact(std::string name) {
  auto* table = _table(name);
  if (table == nullptr) co_return Status::failure("no table " + name);
  auto writing = co_await table->write_lock.lock();
  co_return co_await _compact(*table);
}

// After Macha's pack compaction: the live records written whole to a new file beside the
// old, synced, then renamed over it. A crash before the rename leaves the old log, and the
// stale temporary is removed by the next write. Readers carry on against the old frames
// until the new file is in place.
Task<Status> SealedStore::_compact(Table& table) {
  const auto& name = table.spec.name;
  Bytes file;
  Bytes previous;
  std::map<std::string, SealedFrame, std::less<>> frames;
  std::size_t was = 0;
  std::uint32_t epoch = 0;
  {
    std::lock_guard<std::mutex> lock(table.mutex);
    if (table.broken) co_return Status::failure("table " + name + " is refusing writes");
    epoch = table.epoch;
    was = table.length;

    const auto& key = table.keys.at(epoch);
    const auto header = make_file_header(name, epoch, key, *_random);
    if (!header.ok) co_return Status::failure(header.error);

    file = encode_file_header(header.value);
    previous = header.value.tag();
    for (const auto& [record, entry] : table.entries) {
      const auto old_key = table.keys.find(entry.frame.epoch);
      if (old_key == table.keys.end()) co_return Status::failure("no data key for " + record + "'s epoch");
      auto change = open_frame(entry.frame, name, old_key->second);
      if (!change) co_return Status::failure("record " + record + " does not open");

      auto framed = seal_change(*change, name, epoch, key, previous);
      if (!framed.ok) co_return Status::failure(framed.error);
      file.insert(file.end(), framed.value.bytes.begin(), framed.value.bytes.end());
      previous = framed.value.frame.tag();
      frames.emplace(record, std::move(framed.value.frame));
    }
  }

  const auto size = file.size();
  if (const auto written = co_await _files->write(table.path, std::move(file), true); !written.ok) co_return written;

  {
    std::lock_guard<std::mutex> lock(table.mutex);
    for (auto& [record, frame] : frames) table.entries.find(record)->second.frame = std::move(frame);
    table.last_tag = previous;
    table.length = size;
    table.superseded = 0;
  }
  _logger->info(table.path + ": compacted from " + std::to_string(was) + " bytes to " + std::to_string(size) + " under epoch " + std::to_string(epoch));
  co_return Status::success();
}

Task<Status> SealedStore::rotate(std::string name) {
  auto* table = _table(name);
  if (table == nullptr) co_return Status::failure("no table " + name);

  auto writing = co_await table->write_lock.lock();
  std::uint32_t epoch = 0;
  {
    auto keyring = co_await _keyring_lock.lock();
    const auto rotated = _keyring.rotate(table->spec.name, *_random);
    if (!rotated.ok) co_return Status::failure(rotated.error);
    // Saved before anything is sealed under it: a crash after this leaves a key unused,
    // never a record without its key.
    if (const auto saved = co_await _keyrings->save(_keyring); !saved.ok) co_return saved;

    std::lock_guard<std::mutex> lock(table->mutex);
    table->keys[rotated.value] = _keyring.find(table->spec.name, rotated.value)->key;
    table->epoch = epoch = rotated.value;
  }
  _logger->info("Table " + table->spec.name + " is under data key epoch " + std::to_string(epoch));
  co_return co_await _compact(*table);
}

std::optional<SealedStore::Usage> SealedStore::usage(std::string_view name) const {
  const auto* table = _table(name);
  if (table == nullptr) return std::nullopt;
  std::lock_guard<std::mutex> lock(table->mutex);
  return Usage{table->length, table->superseded, table->epoch};
}

}  // namespace lugh::store

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>

#include "lugh/system/files.h"

// Files held in a map, answered at once. `fail_writes` makes every write answer as a full
// disk does. Thread-safe, as the real one is.
class MemoryFiles : public lugh::system::Files {
 public:
  lugh::Task<bool> exists(std::string path) const override { co_return exists_now(path); }

  lugh::Task<lugh::Result<lugh::Bytes>> read(std::string path, std::size_t most) const override { co_return read_now(path, most); }

  lugh::Task<lugh::Result<lugh::SecureBytes>> read_secret(std::string path, std::size_t most) const override {
    auto plain = read_now(path, most);
    if (!plain.ok) co_return lugh::Result<lugh::SecureBytes>::failure(plain.error);
    co_return lugh::Result<lugh::SecureBytes>::success(lugh::SecureBytes(plain.value.begin(), plain.value.end()));
  }

  lugh::Task<lugh::Status> write(std::string path, lugh::Bytes data, bool replace) override {
    std::lock_guard<std::mutex> lock(_mutex);
    if (fail_writes) co_return lugh::Status::failure("cannot write " + path + ": No space left on device");
    if (!replace && _files.count(path) != 0) co_return lugh::Status::failure(path + " exists, and is not replaced");
    _files[path] = std::move(data);
    ++writes;
    co_return lugh::Status::success();
  }

  lugh::Task<lugh::Status> append(std::string path, lugh::Bytes data) override {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto found = _files.find(path);
    if (found == _files.end()) co_return lugh::Status::failure("cannot append to " + path + ": No such file or directory");
    if (tear_next_append) {
      // A crash part way through: some of the bytes land, and the caller hears it failed.
      const auto landed = std::min(*tear_next_append, data.size());
      found->second.insert(found->second.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(landed));
      tear_next_append.reset();
      co_return lugh::Status::failure("cannot append to " + path + ": Input/output error");
    }
    if (fail_writes) co_return lugh::Status::failure("cannot append to " + path + ": No space left on device");
    found->second.insert(found->second.end(), data.begin(), data.end());
    ++writes;
    co_return lugh::Status::success();
  }

  lugh::Task<lugh::Status> truncate(std::string path, std::uint64_t size) override {
    std::lock_guard<std::mutex> lock(_mutex);
    if (fail_truncate) co_return lugh::Status::failure("cannot truncate " + path + ": Input/output error");
    const auto found = _files.find(path);
    if (found == _files.end()) co_return lugh::Status::failure("cannot truncate " + path + ": No such file or directory");
    found->second.resize(static_cast<std::size_t>(size));
    co_return lugh::Status::success();
  }

  lugh::Task<lugh::Status> remove(std::string path) override {
    std::lock_guard<std::mutex> lock(_mutex);
    _files.erase(path);
    co_return lugh::Status::success();
  }

  lugh::Task<lugh::Status> make_directory(std::string path) override {
    std::lock_guard<std::mutex> lock(_mutex);
    _directories.insert(path);
    co_return lugh::Status::success();
  }

  // For the test itself, which is not a coroutine.
  void put(const std::string& path, lugh::Bytes data) {
    std::lock_guard<std::mutex> lock(_mutex);
    _files[path] = std::move(data);
  }

  std::optional<lugh::Bytes> get(const std::string& path) const {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto found = _files.find(path);
    if (found == _files.end()) return std::nullopt;
    return found->second;
  }

  bool exists_now(const std::string& path) const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _files.count(path) != 0 || _directories.count(path) != 0;
  }

  std::atomic<bool> fail_writes{false};
  std::atomic<bool> fail_truncate{false};
  // The next append lands only this many bytes, then fails.
  std::optional<std::size_t> tear_next_append;
  std::atomic<int> writes{0};

 private:
  lugh::Result<lugh::Bytes> read_now(const std::string& path, std::size_t most) const {
    std::lock_guard<std::mutex> lock(_mutex);
    const auto found = _files.find(path);
    if (found == _files.end()) return lugh::Result<lugh::Bytes>::failure("cannot read " + path + ": No such file or directory");
    if (found->second.size() > most) return lugh::Result<lugh::Bytes>::failure(path + " is larger than " + std::to_string(most) + " bytes");
    return lugh::Result<lugh::Bytes>::success(found->second);
  }

  mutable std::mutex _mutex;
  std::map<std::string, lugh::Bytes> _files;
  std::set<std::string> _directories;
};

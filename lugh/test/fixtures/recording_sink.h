//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/status/log.h"

// A sink that keeps every record, at every level, for tests about what the node logs.
class RecordingSink : public dannan::status::LogSink {
 public:
  bool enabled(dannan::status::LogLevel) const noexcept override { return true; }

  void write(dannan::status::LogLevel level, std::string_view scope, std::string_view message) override {
    std::lock_guard<std::mutex> lock(_mutex);
    _records.push_back({level, std::string(scope), std::string(message)});
  }

  // Every message, in order, optionally of one level only.
  std::vector<std::string> lines() const {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<std::string> found;
    for (const auto& record : _records) found.push_back(record.message);
    return found;
  }

  std::vector<std::string> lines(dannan::status::LogLevel level) const {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<std::string> found;
    for (const auto& record : _records) {
      if (record.level == level) found.push_back(record.message);
    }
    return found;
  }

  // The whole log as one string, "scope: message" a line, for asking whether something was
  // said at all.
  std::string text() const {
    std::lock_guard<std::mutex> lock(_mutex);
    std::string all;
    for (const auto& record : _records) all += record.scope + ": " + record.message + "\n";
    return all;
  }

 private:
  struct Record {
    dannan::status::LogLevel level;
    std::string scope;
    std::string message;
  };

  mutable std::mutex _mutex;
  std::vector<Record> _records;
};

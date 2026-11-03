//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "lugh/loggers/logger.h"

// A silent logger that records every line, for tests about what the service logs.
class MockLogger : public lugh::loggers::Logger {
 public:
  void debug(const std::string& log) override { _record(lugh::loggers::DEBUG, log); }
  void info(const std::string& log) override { _record(lugh::loggers::INFO, log); }
  void warn(const std::string& log) override { _record(lugh::loggers::WARN, log); }
  void error(const std::string& log) override { _record(lugh::loggers::ERROR, log); }
  void raw(const std::string& log) override { _record(lugh::loggers::INFO, log); }

  void set_level(lugh::loggers::LogLevel) override {}
  std::shared_ptr<lugh::loggers::Logger> base_logger() override { return nullptr; }

  // Everything logged, in order, optionally of one level only.
  std::vector<std::string> lines() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _lines;
  }

  std::vector<std::string> lines(lugh::loggers::LogLevel level) const {
    std::lock_guard<std::mutex> lock(_mutex);

    std::vector<std::string> found;
    for (std::size_t i = 0; i < _lines.size(); ++i) {
      if (_levels[i] == level) found.push_back(_lines[i]);
    }
    return found;
  }

  // The whole log as one string, for asking whether something was said at all.
  std::string text() const {
    std::lock_guard<std::mutex> lock(_mutex);

    std::string all;
    for (const auto& line : _lines) all += line + "\n";
    return all;
  }

 private:
  void _record(lugh::loggers::LogLevel level, const std::string& log) {
    std::lock_guard<std::mutex> lock(_mutex);
    _lines.push_back(log);
    _levels.push_back(level);
  }

  mutable std::mutex _mutex;
  std::vector<std::string> _lines;
  std::vector<lugh::loggers::LogLevel> _levels;
};

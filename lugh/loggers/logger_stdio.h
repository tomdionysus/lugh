//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <atomic>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#include "lugh/loggers/logger.h"

namespace lugh::loggers {

// The one sink: a line per message to a stream, standard output by default, which systemd
// hands to the journal. An adapter: it reads the wall clock to stamp each line.
class LoggerStdIO : public Logger {
 public:
  // Writes to standard output by default; tests pass their own stream.
  explicit LoggerStdIO(LogLevel log_level, std::ostream& out = std::cout);

  void debug(const std::string& log) override;
  void info(const std::string& log) override;
  void warn(const std::string& log) override;
  void error(const std::string& log) override;
  void raw(const std::string& log) override;
  std::shared_ptr<Logger> base_logger() override;
  void set_level(LogLevel level) override;

  // Set once the configuration has been read.
  void set_format(LogFormat format);

 private:
  void _write(const char* text_level, const char* json_level, const std::string& log);

  // Atomic: both are read on every line from any thread, outside the mutex, and set once
  // from main after the configuration is read.
  std::atomic<LogLevel> _log_level;
  std::atomic<LogFormat> _format{LogFormat::Text};
  std::ostream& _out;
  std::mutex _mutex;
};

}  // namespace lugh::loggers

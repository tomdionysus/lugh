//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>

namespace lugh::loggers {

// Unscoped, as AthenaSIP's and blackraven-admin's are, so code lifted from them compiles
// unchanged. Nothing in this project may define a DEBUG or ERROR macro.
enum LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

// Text for a terminal or the journal; Json is one object per line, for a log shipper.
enum class LogFormat { Text, Json };

// Every line is a std::string, and a Secret (core/secret.h) is not one and does not become
// one, so a secret cannot be logged without first being spelled out as revealed.
class Logger {
 public:
  virtual ~Logger() {}
  virtual void debug(const std::string& log) = 0;
  virtual void info(const std::string& log) = 0;
  virtual void warn(const std::string& log) = 0;
  virtual void error(const std::string& log) = 0;
  virtual void raw(const std::string& log) = 0;
  virtual void set_level(LogLevel level) = 0;

  virtual std::shared_ptr<Logger> base_logger() = 0;
};

}  // namespace lugh::loggers

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/loggers/logger_stdio.h"

#include <boost/json.hpp>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace lugh::loggers {

namespace {

std::string zulu_time() {
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm parts{};
  gmtime_r(&now, &parts);

  std::ostringstream out;
  out << std::put_time(&parts, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}

}  // namespace

LoggerStdIO::LoggerStdIO(LogLevel log_level, std::ostream& out) : _log_level(log_level), _out(out) {}

void LoggerStdIO::debug(const std::string& log) {
  if (_log_level > LogLevel::DEBUG) return;
  _write("[DEBUG]", "debug", log);
}

void LoggerStdIO::info(const std::string& log) {
  if (_log_level > LogLevel::INFO) return;
  _write("[INFO ]", "info", log);
}

void LoggerStdIO::warn(const std::string& log) {
  if (_log_level > LogLevel::WARN) return;
  _write("[WARN ]", "warn", log);
}

void LoggerStdIO::error(const std::string& log) { _write("[ERROR]", "error", log); }

void LoggerStdIO::raw(const std::string& log) { _write("[-----]", "raw", log); }

// A scoped logger prefixes the line with "(scope) " per nesting level, outermost first.
// JSON output lifts those into a field of their own, so a shipper can filter by component.
void LoggerStdIO::_write(const char* text_level, const char* json_level, const std::string& log) {
  const auto at = zulu_time();

  if (_format == LogFormat::Text) {
    std::lock_guard<std::mutex> lock(_mutex);
    _out << at << " " << text_level << " " << log << std::endl;
    return;
  }

  std::string scope;
  std::size_t start = 0;
  while (start < log.size() && log[start] == '(') {
    const auto close = log.find(") ", start);
    if (close == std::string::npos) break;

    if (!scope.empty()) scope += "/";
    scope += log.substr(start + 1, close - start - 1);
    start = close + 2;
  }

  boost::json::object line;
  line["at"] = at;
  line["level"] = json_level;
  if (!scope.empty()) line["scope"] = scope;
  line["message"] = log.substr(start);

  const auto text = boost::json::serialize(line);

  std::lock_guard<std::mutex> lock(_mutex);
  _out << text << std::endl;
}

std::shared_ptr<Logger> LoggerStdIO::base_logger() { return nullptr; }

void LoggerStdIO::set_level(LogLevel level) { _log_level = level; }

void LoggerStdIO::set_format(LogFormat format) { _format = format; }

}  // namespace lugh::loggers

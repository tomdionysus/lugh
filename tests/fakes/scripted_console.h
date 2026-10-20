#pragma once

#include <deque>
#include <string>
#include <utility>
#include <vector>

#include "system/console.h"

// A person who types the lines given, in order, and then nothing. Every prompt is kept.
class ScriptedConsole : public lugh::system::Console {
 public:
  ScriptedConsole() = default;
  explicit ScriptedConsole(std::vector<std::string> lines) : _lines(lines.begin(), lines.end()) {}

  lugh::Task<std::optional<lugh::Secret>> read_secret(std::string prompt) override {
    prompts.push_back(prompt);
    if (_lines.empty()) co_return std::nullopt;
    lugh::Secret line(_lines.front());
    _lines.pop_front();
    co_return line;
  }

  void show_secret(const std::string& label, const lugh::Secret& secret) override { shown.emplace_back(label, std::string(secret.reveal())); }

  void type(const std::string& line) { _lines.push_back(line); }

  std::vector<std::string> prompts;
  std::vector<std::pair<std::string, std::string>> shown;

 private:
  std::deque<std::string> _lines;
};

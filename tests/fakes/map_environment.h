#pragma once

#include <map>
#include <string>

#include "system/environment.h"

// An environment holding exactly what the test put in it.
class MapEnvironment : public lugh::system::Environment {
 public:
  MapEnvironment() = default;
  explicit MapEnvironment(std::map<std::string, std::string> values) : _values(std::move(values)) {}

  std::optional<std::string> get(const std::string& name) const override {
    const auto found = _values.find(name);
    if (found == _values.end()) return std::nullopt;
    return found->second;
  }

  void set(const std::string& name, const std::string& value) { _values[name] = value; }

 private:
  std::map<std::string, std::string> _values;
};

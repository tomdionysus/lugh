#pragma once

#include <optional>
#include <string>

namespace lugh::system {

// The process environment, from outside, so the configuration loader can be tested
// without setting variables on the test process.
class Environment {
 public:
  virtual ~Environment() = default;

  // nullopt when the variable is not set; set but empty is an empty string.
  virtual std::optional<std::string> get(const std::string& name) const = 0;
};

}  // namespace lugh::system

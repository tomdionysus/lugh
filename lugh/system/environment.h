//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

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

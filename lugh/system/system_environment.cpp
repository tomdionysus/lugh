//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "system/system_environment.h"

#include <cstdlib>

namespace lugh::system {

std::optional<std::string> SystemEnvironment::get(const std::string& name) const {
  const char* value = std::getenv(name.c_str());
  if (!value) return std::nullopt;
  return std::string(value);
}

}  // namespace lugh::system

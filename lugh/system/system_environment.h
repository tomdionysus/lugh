//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "lugh/system/environment.h"

namespace lugh::system {

class SystemEnvironment : public Environment {
 public:
  std::optional<std::string> get(const std::string& name) const override;
};

}  // namespace lugh::system

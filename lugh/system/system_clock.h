//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "system/clock.h"

namespace lugh::system {

class SystemClock : public Clock {
 public:
  std::chrono::system_clock::time_point wall_now() const override;
  std::chrono::steady_clock::time_point steady_now() const override;
};

}  // namespace lugh::system

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <mutex>

#include "lugh/system/clock.h"

// A clock that moves only when the test says.
class ManualClock : public lugh::system::Clock {
 public:
  std::chrono::system_clock::time_point wall_now() const override {
    std::lock_guard<std::mutex> lock(_mutex);
    return _wall;
  }

  std::chrono::steady_clock::time_point steady_now() const override {
    std::lock_guard<std::mutex> lock(_mutex);
    return _steady;
  }

  void advance(std::chrono::milliseconds by) {
    std::lock_guard<std::mutex> lock(_mutex);
    _wall += by;
    _steady += by;
  }

 private:
  mutable std::mutex _mutex;
  std::chrono::system_clock::time_point _wall{std::chrono::seconds(1792281600)};  // 2026-10-18T00:00:00Z
  std::chrono::steady_clock::time_point _steady{std::chrono::hours(1)};
};

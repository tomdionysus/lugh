//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstdint>

namespace lugh::system {

// Time, from outside. Nothing but an adapter reads a clock itself, so a test can say what
// time it is.
class Clock {
 public:
  virtual ~Clock() = default;

  // For timestamps a person or another machine reads.
  virtual std::chrono::system_clock::time_point wall_now() const = 0;

  // For intervals: never goes backwards.
  virtual std::chrono::steady_clock::time_point steady_now() const = 0;
};

// Whole seconds since the epoch, as records store a time.
inline std::uint64_t unix_seconds(const Clock& clock) {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(clock.wall_now().time_since_epoch()).count());
}

}  // namespace lugh::system

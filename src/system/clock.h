#pragma once

#include <chrono>

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

}  // namespace lugh::system

#pragma once

#include "system/clock.h"

namespace lugh::system {

class SystemClock : public Clock {
 public:
  std::chrono::system_clock::time_point wall_now() const override;
  std::chrono::steady_clock::time_point steady_now() const override;
};

}  // namespace lugh::system

#include "system/system_clock.h"

namespace lugh::system {

std::chrono::system_clock::time_point SystemClock::wall_now() const { return std::chrono::system_clock::now(); }

std::chrono::steady_clock::time_point SystemClock::steady_now() const { return std::chrono::steady_clock::now(); }

}  // namespace lugh::system

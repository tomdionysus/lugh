//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <string>
#include <string_view>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"

namespace lugh::session {

// The sudo window (TODO/2026-11-15-self-factors.md, the maintainer 2026-11-15): a session whose person has
// just proved an existing factor may change their factors for a while without proving one again.
// Held by sid, node-local and in memory, so a restart closes every window, which fails closed. A
// sid is random and never reused, so an ended session's window is simply left to close.
// Past `most` the window closing soonest goes first, which also fails closed. Safe from any
// number of threads.
class Reauthentications {
 public:
  static constexpr std::chrono::seconds kWindow = std::chrono::minutes(10);

  explicit Reauthentications(const dannan::contract::TimeSource& time, std::chrono::seconds window = kWindow, std::size_t most = 10000);

  // Opens the session's window, from now; answers when it closes.
  dannan::contract::TimePoint open(std::string_view sid);
  // Whether the session's window is open now.
  bool open_now(std::string_view sid) const;

  std::chrono::seconds window() const { return _window; }

 private:
  const dannan::contract::TimeSource& _time;
  std::chrono::seconds _window;
  std::size_t _most;

  mutable dannan::contract::Mutex _mutex;
  // Each open window and when it closes.
  std::map<std::string, dannan::contract::TimePoint, std::less<>> _until DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::session

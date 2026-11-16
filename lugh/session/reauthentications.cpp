//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/session/reauthentications.h"

#include <algorithm>

namespace lugh::session {

Reauthentications::Reauthentications(const dannan::contract::TimeSource& time, std::chrono::seconds window, std::size_t most)
    : _time(time), _window(window), _most(most == 0 ? 1 : most) {}

dannan::contract::TimePoint Reauthentications::open(std::string_view sid) {
  const auto now = _time.now();
  const auto until = now + _window;
  dannan::contract::Lock state(_mutex);
  // The closed go first; then, if still full, the one closing soonest.
  std::erase_if(_until, [&](const auto& one) { return one.second <= now; });
  const auto found = _until.find(sid);
  if (found != _until.end()) {
    found->second = until;
    return until;
  }
  if (_until.size() >= _most) {
    _until.erase(std::min_element(_until.begin(), _until.end(), [](const auto& a, const auto& b) { return a.second < b.second; }));
  }
  _until.emplace(std::string(sid), until);
  return until;
}

bool Reauthentications::open_now(std::string_view sid) const {
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  const auto found = _until.find(sid);
  return found != _until.end() && now < found->second;
}

}  // namespace lugh::session

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <atomic>
#include <mutex>

#include "system/random.h"

// Bytes that are different every call and the same every run: 0, 1, 2, ... carrying on
// across calls. `fail` makes it answer as a broken source does. Thread-safe, as the real
// one is.
class FixedRandom : public lugh::system::Random {
 public:
  bool fill(std::span<unsigned char> out) override {
    std::lock_guard<std::mutex> lock(_mutex);
    if (fail) return false;
    for (auto& byte : out) byte = static_cast<unsigned char>(_next++);
    return true;
  }

  std::atomic<bool> fail{false};

 private:
  std::mutex _mutex;
  unsigned _next = 0;
};

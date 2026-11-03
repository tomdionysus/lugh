//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>

#include "dannan/identity/crypto.h"
#include "lugh/system/random.h"

// Bytes that never repeat within a test and are the same every run: SHA-256 of a counter.
// FixedRandom's bytes come round every 256, which is too soon for IDs, salts and secrets
// made side by side. `fail` makes it answer as a broken source does. Thread-safe, as the
// real one is.
class CountingRandom : public lugh::system::Random {
 public:
  bool fill(std::span<unsigned char> out) override {
    std::lock_guard<std::mutex> lock(_mutex);
    if (fail) return false;
    std::size_t done = 0;
    while (done < out.size()) {
      unsigned char counter[8];
      for (int i = 0; i < 8; ++i) counter[i] = static_cast<unsigned char>(_next >> (8 * i));
      ++_next;
      const auto block = dannan::identity::sha256(counter).bytes;
      for (std::size_t i = 0; i < block.size() && done < out.size(); ++i) out[done++] = block[i];
    }
    return true;
  }

  std::atomic<bool> fail{false};

 private:
  std::mutex _mutex;
  std::uint64_t _next = 0;
};

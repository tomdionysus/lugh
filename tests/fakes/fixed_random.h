#pragma once

#include "system/random.h"

// Bytes that are different every call and the same every run: 0, 1, 2, ... carrying on
// across calls. `fail` makes it answer as a broken source does.
class FixedRandom : public lugh::system::Random {
 public:
  std::vector<unsigned char> bytes(std::size_t count) override {
    if (fail) return {};
    std::vector<unsigned char> out(count);
    for (auto& byte : out) byte = static_cast<unsigned char>(_next++);
    return out;
  }

  bool fail = false;

 private:
  unsigned _next = 0;
};

#pragma once

#include <cstddef>
#include <vector>

namespace lugh::system {

// Cryptographically strong random bytes, from outside, so a test can say what they are.
class Random {
 public:
  virtual ~Random() = default;

  // Empty when the source failed, which the caller must treat as a failure, never as
  // "zero bytes of randomness".
  virtual std::vector<unsigned char> bytes(std::size_t count) = 0;
};

}  // namespace lugh::system

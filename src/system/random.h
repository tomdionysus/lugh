#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace lugh::system {

// Cryptographically strong random bytes, from outside, so a test can say what they are.
class Random {
 public:
  virtual ~Random() = default;

  // Fills the buffer it is given, so a key can be made where it will live (SecureBytes)
  // and nowhere else. False when the source failed, and then the buffer means nothing.
  virtual bool fill(std::span<unsigned char> out) = 0;

  // For bytes that are not secret: a nonce, a salt, an identifier. Empty when the source
  // failed, which the caller must treat as a failure, never as "zero bytes of randomness".
  std::vector<unsigned char> bytes(std::size_t count) {
    std::vector<unsigned char> out(count);
    if (count != 0 && !fill(out)) return {};
    return out;
  }
};

}  // namespace lugh::system

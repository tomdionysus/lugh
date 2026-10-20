#pragma once

#include "system/random.h"

namespace lugh::system {

// OpenSSL's CSPRNG.
class SystemRandom : public Random {
 public:
  bool fill(std::span<unsigned char> out) override;
};

}  // namespace lugh::system

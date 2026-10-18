#pragma once

#include "system/random.h"

namespace lugh::system {

// OpenSSL's CSPRNG.
class SystemRandom : public Random {
 public:
  std::vector<unsigned char> bytes(std::size_t count) override;
};

}  // namespace lugh::system

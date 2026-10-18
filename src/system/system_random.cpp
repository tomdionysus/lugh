#include "system/system_random.h"

#include <openssl/rand.h>

namespace lugh::system {

std::vector<unsigned char> SystemRandom::bytes(std::size_t count) {
  std::vector<unsigned char> out(count);
  if (count == 0) return out;
  if (RAND_bytes(out.data(), static_cast<int>(count)) != 1) return {};
  return out;
}

}  // namespace lugh::system

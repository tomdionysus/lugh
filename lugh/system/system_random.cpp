//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/system/system_random.h"

#include <openssl/rand.h>

#include <climits>

namespace lugh::system {

bool SystemRandom::fill(std::span<unsigned char> out) {
  if (out.empty()) return true;
  if (out.size() > static_cast<std::size_t>(INT_MAX)) return false;
  return RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

}  // namespace lugh::system

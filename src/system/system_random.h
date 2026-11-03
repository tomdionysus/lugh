//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "system/random.h"

namespace lugh::system {

// OpenSSL's CSPRNG.
class SystemRandom : public Random {
 public:
  bool fill(std::span<unsigned char> out) override;
};

}  // namespace lugh::system

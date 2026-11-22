//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// libFuzzer's entry, for a binary built of one target (lugh/fuzz/CMakeLists.txt): each input
// through the targets registered in it, which is that one.

#include <cstddef>
#include <cstdint>

#include "dannan/fuzz/fuzz.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  dannan::fuzz::run_all(dannan::fuzz::targets(), {data, size});
  return 0;
}

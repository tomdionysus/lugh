//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A record envelope, as another node's commit carries it: what decodes must encode to the same bytes, and merge with itself
// to itself.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/merge/record_merge.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::merge;
  const std::span<const unsigned char> bytes(data, size);
  const auto envelope = decode(bytes);
  if (!envelope) return 0;
  const auto again = encode(*envelope);
  if (again.size() != size || !std::equal(again.begin(), again.end(), bytes.begin())) std::abort();
  const Records one{{"k", *envelope}};
  if (merge(std::nullopt, {one, one}) != one) std::abort();
  return 0;
}

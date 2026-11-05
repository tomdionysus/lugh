//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A DN, as a bind or a search names one. What parses must survive being written and read again.

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "lugh/ldap/dn.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::ldap;
  const auto parsed = parse_dn(std::string_view(reinterpret_cast<const char*>(data), size));
  if (!parsed) return 0;
  const auto again = parse_dn(to_string(*parsed));
  if (!again || *again != *parsed) __builtin_trap();
  (void)within(normalised(*parsed), normalised(*again));
  return 0;
}

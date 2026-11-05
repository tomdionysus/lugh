//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A search filter, parsed and evaluated, which a bound client chooses freely.

#include <cstddef>
#include <cstdint>
#include <span>

#include "lugh/ldap/filter.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::ldap;
  ber::Reader reader(std::span<const unsigned char>(data, size));
  const auto element = reader.next();
  if (!element) return 0;
  const auto filter = parse_filter(*element);
  if (!filter) return 0;

  Entry entry;
  entry.dn = "uid=alice,ou=people,dc=example,dc=com";
  entry.add("uid", "alice");
  entry.add("uidNumber", "1000");
  entry.add("memberOf", "cn=staff,ou=groups,dc=example,dc=com");
  (void)filter->evaluate(entry);
  (void)filter->evaluate(Entry{});
  (void)pinned_value(*filter, "uid");
  return 0;
}

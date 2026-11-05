//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "lugh/ldap/ber.h"

namespace lugh::ldap {

inline constexpr int kMostFilterDepth = 16;
inline constexpr std::size_t kMostFilterItems = 1024;

// What a search reads: a generated view of a user, a group or the tree. Attribute names are folded
// to lower case.
struct Entry {
  std::string dn;
  std::map<std::string, std::vector<std::string>> attributes;

  void add(std::string_view name, std::string value);
};

// RFC 4511 section 4.5.1.7's three values.
enum class Match { yes, no, undefined };

// A search filter (TODO/2026-11-04-ldap.md, "Filters").
struct Filter {
  enum class Kind {
    all_of,
    any_of,
    negated,
    equal,
    substring,
    greater_or_equal,
    less_or_equal,
    present,
    approximate,
    // extensibleMatch: taken apart no further, and always Undefined.
    unsupported,
  };

  Kind kind = Kind::present;
  std::vector<Filter> children;
  // Folded.
  std::string attribute;
  std::string value;
  std::optional<std::string> initial;
  std::vector<std::string> any;
  std::optional<std::string> last;

  Match evaluate(const Entry& entry) const;
};

// Nothing for what is not a filter, is nested past kMostFilterDepth or holds more than
// kMostFilterItems items.
std::optional<Filter> parse_filter(const ber::Element& element);

// The value a filter pins `attribute` to by equality, alone or as one term of an `and`, so a search
// can go straight to that one entry (TODO/2026-11-04-ldap.md, "Filters").
std::optional<std::string> pinned_value(const Filter& filter, std::string_view attribute);

}  // namespace lugh::ldap

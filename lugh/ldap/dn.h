//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Distinguished names (RFC 4514), only in the forms Lugh's tree has: one attribute to a component,
// by name and not by OID, with a string value. The empty DN is the rootDSE.
namespace lugh::ldap {

inline constexpr std::size_t kMostDnComponents = 16;

struct Rdn {
  // Lower case.
  std::string type;
  // Unescaped, as written.
  std::string value;

  bool operator==(const Rdn&) const = default;
};

struct Dn {
  // The leaf first, as written.
  std::vector<Rdn> rdns;

  bool empty() const { return rdns.empty(); }
  bool operator==(const Dn&) const = default;
};

// Nothing for anything else: a multi-valued component, an OID, a #hex value, a bad escape, a NUL,
// an unescaped special, an empty type or value, or more than kMostDnComponents components.
std::optional<Dn> parse_dn(std::string_view text);

// RFC 4514's string form: canonical types, and the value escaped where it must be.
std::string to_string(const Dn& dn);

// `value` escaped for a DN.
std::string escape_dn_value(std::string_view value);

// The form DNs are compared in: every type and value folded, so equal names are equal strings.
Dn normalised(const Dn& dn);

// Whether `dn` is `ancestor`, or below it. Both normalised.
bool within(const Dn& dn, const Dn& ancestor);

// ASCII folded to lower case, as the matching rules Lugh's attributes use. Other bytes are left.
std::string fold(std::string_view text);

}  // namespace lugh::ldap

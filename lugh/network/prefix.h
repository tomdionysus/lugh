//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <stdexcept>
#include <string_view>

#include "dannan/listen/limits.h"

// Address ranges are the stack's, Dannan's listen::Prefix: the proxies the listener trusts and
// the networks an app password is limited to. Host bits set past the length are refused
// ("10.0.0.1/8" is a mistake, not 10.0.0.0/8), and an IPv4-mapped address is its IPv4 one.
namespace lugh::network {

using dannan::listen::Prefix;
using dannan::listen::unmapped;

// `text` as a range, or nothing for anything that is not one: for a value a person typed,
// refused with the caller's own words.
inline std::optional<Prefix> prefix_of(std::string_view text) {
  try {
    return Prefix::parse(text);
  } catch (const std::invalid_argument&) {
    return std::nullopt;
  }
}

}  // namespace lugh::network

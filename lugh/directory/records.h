//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "lugh/core/secure_bytes.h"
#include "lugh/store/store.h"

namespace lugh::directory {

// A person signs in; a service uses client credentials (P6) or an app password (P11), and
// has no password or second factor of its own.
enum class Kind : std::uint8_t { person = 1, service = 2 };

struct User {
  // The record's key, and its version in the store; neither is in the value.
  std::string id;
  std::uint64_t version = 0;

  Kind kind = Kind::person;
  // Has set a password and a second factor. Until then a sign-in reaches enrolment and
  // nothing else.
  bool enrolled = false;
  bool disabled = false;
  // Lower case, as normal_name() makes it. Unique.
  std::string name;
  // Lower case. Unique when present; root has none, nor need a service.
  std::string email;
  std::string display_name;
  // Seconds since the epoch.
  std::uint64_t created = 0;
  std::uint64_t updated = 0;
};

struct Group {
  std::string id;
  std::uint64_t version = 0;

  std::string name;
  std::string description;
  std::uint64_t created = 0;
  std::uint64_t updated = 0;
};

// One user in one group. Keyed "<group>/<user>/<instance>", because a removal is final
// and the same user may join the same group again later.
struct Membership {
  std::string key;
  std::string group_id;
  std::string user_id;
  std::uint64_t added = 0;
};

inline constexpr const char* kUsers = "users";
inline constexpr const char* kGroups = "groups";
inline constexpr const char* kMemberships = "memberships";

inline constexpr std::size_t kMostNameBytes = 64;
inline constexpr std::size_t kMostEmailBytes = 254;
inline constexpr std::size_t kMostDisplayBytes = 128;
inline constexpr std::size_t kMostDescriptionBytes = 1024;

// A name as stored: ASCII letters (folded to lower case), digits, '.', '_' and '-',
// starting with a letter or digit, at most kMostNameBytes. nullopt for anything else, so
// two names that look alike to a person cannot both exist.
std::optional<std::string> normal_name(std::string_view text);

// An address as stored, folded to lower case: one '@', something either side, a dot in
// the domain, no spaces or control characters. Not RFC 5322; enough to refuse a mistake.
std::optional<std::string> normal_email(std::string_view text);

// Printable: no control characters, valid UTF-8, within `most` bytes.
bool printable(std::string_view text, std::size_t most);

// SecureBytes: a record of a person is theirs, and is sealed before it leaves memory.
SecureBytes encode(const User& user);
std::optional<User> decode_user(std::span<const unsigned char> value);
SecureBytes encode(const Group& group);
std::optional<Group> decode_group(std::span<const unsigned char> value);
SecureBytes encode(const Membership& membership);
std::optional<Membership> decode_membership(std::span<const unsigned char> value);

// The directory's tables, with their indexes: users by name and email, groups by name.
std::vector<store::TableSpec> table_specs();

}  // namespace lugh::directory

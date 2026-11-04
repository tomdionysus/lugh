//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/directory/records.h"

#include "lugh/core/codec.h"

namespace lugh::directory {

namespace {

// Format 1 had no name parts and no POSIX number; it is still read, since the frozen store
// holds records in it, and never written again.
constexpr std::uint8_t kFormat1 = 1;
constexpr std::uint8_t kFormat = 2;
constexpr std::uint8_t kEnrolled = 0x01;
constexpr std::uint8_t kDisabled = 0x02;

void write_posix(SecureWriter& writer, const std::optional<std::uint32_t>& number) {
  writer.u8(number ? 1 : 0);
  writer.u32(number.value_or(0));
}

std::optional<std::optional<std::uint32_t>> read_posix(dannan::net::Reader& reader) {
  const auto present = reader.u8();
  const auto number = reader.u32();
  if (present > 1 || (present == 0 && number != 0)) return std::nullopt;
  return present ? std::optional<std::uint32_t>(number) : std::nullopt;
}

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool letter_or_digit(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }

// The length of the UTF-8 sequence starting at `at`, or 0 for one that is not valid:
// overlong forms, surrogates and values past U+10FFFF included.
std::size_t utf8_length(std::string_view text, std::size_t at) {
  const auto byte = [&](std::size_t i) { return static_cast<unsigned char>(text[i]); };
  const auto first = byte(at);
  if (first < 0x80) return 1;

  std::size_t length;
  unsigned value;
  if ((first & 0xe0) == 0xc0) {
    length = 2;
    value = first & 0x1f;
  } else if ((first & 0xf0) == 0xe0) {
    length = 3;
    value = first & 0x0f;
  } else if ((first & 0xf8) == 0xf0) {
    length = 4;
    value = first & 0x07;
  } else {
    return 0;
  }
  if (at + length > text.size()) return 0;
  for (std::size_t i = 1; i < length; ++i) {
    if ((byte(at + i) & 0xc0) != 0x80) return 0;
    value = (value << 6) | (byte(at + i) & 0x3f);
  }

  static constexpr unsigned kLeast[] = {0, 0, 0x80, 0x800, 0x10000};
  if (value < kLeast[length] || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return 0;
  // C1 controls.
  if (value >= 0x80 && value <= 0x9f) return 0;
  return length;
}

template <typename Write>
SecureBuffer encoded(Write write) {
  SecureWriter writer;
  writer.u8(kFormat);
  write(writer);
  return writer.take();
}

}  // namespace

std::optional<std::string> normal_name(std::string_view text) {
  if (text.empty() || text.size() > kMostNameBytes) return std::nullopt;
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    const char folded = lower(c);
    if (!letter_or_digit(folded) && folded != '.' && folded != '_' && folded != '-') return std::nullopt;
    out.push_back(folded);
  }
  if (!letter_or_digit(out.front())) return std::nullopt;
  return out;
}

std::optional<std::string> normal_email(std::string_view text) {
  if (text.size() < 3 || text.size() > kMostEmailBytes) return std::nullopt;
  const auto at = text.find('@');
  if (at == std::string_view::npos || at == 0 || at + 1 == text.size() || text.find('@', at + 1) != std::string_view::npos) return std::nullopt;

  const auto domain = text.substr(at + 1);
  const auto dot = domain.find('.');
  if (dot == std::string_view::npos || dot == 0 || domain.back() == '.') return std::nullopt;

  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte <= 0x20 || byte == 0x7f || byte >= 0x80) return std::nullopt;
    out.push_back(lower(c));
  }
  return out;
}

bool printable(std::string_view text, std::size_t most) {
  if (text.size() > most) return false;
  for (std::size_t i = 0; i < text.size();) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte < 0x20 || byte == 0x7f) return false;
    const auto length = utf8_length(text, i);
    if (length == 0) return false;
    i += length;
  }
  return true;
}

SecureBuffer encode(const User& user) {
  return encoded([&](SecureWriter& writer) {
    writer.u8(static_cast<std::uint8_t>(user.kind));
    writer.u8(static_cast<std::uint8_t>((user.enrolled ? kEnrolled : 0) | (user.disabled ? kDisabled : 0)));
    writer.string(user.name);
    writer.string(user.email);
    writer.string(user.display_name);
    writer.string(user.given_name);
    writer.string(user.family_name);
    write_posix(writer, user.posix_number);
    writer.u64(user.created);
    writer.u64(user.updated);
  });
}

std::optional<User> decode_user(std::span<const unsigned char> value) {
  return decode_whole<User>(value, [](dannan::net::Reader& reader) -> std::optional<User> {
    const auto format = reader.u8();
    if (format != kFormat1 && format != kFormat) return std::nullopt;
    const auto kind = reader.u8();
    const auto flags = reader.u8();
    if (kind != static_cast<std::uint8_t>(Kind::person) && kind != static_cast<std::uint8_t>(Kind::service)) return std::nullopt;
    if ((flags & ~(kEnrolled | kDisabled)) != 0) return std::nullopt;

    User user;
    user.kind = static_cast<Kind>(kind);
    user.enrolled = (flags & kEnrolled) != 0;
    user.disabled = (flags & kDisabled) != 0;
    user.name = reader.string(kMostFieldBytes);
    user.email = reader.string(kMostFieldBytes);
    user.display_name = reader.string(kMostFieldBytes);
    if (format == kFormat) {
      user.given_name = reader.string(kMostFieldBytes);
      user.family_name = reader.string(kMostFieldBytes);
      const auto posix = read_posix(reader);
      if (!posix) return std::nullopt;
      user.posix_number = *posix;
    }
    user.created = reader.u64();
    user.updated = reader.u64();
    return user;
  });
}

SecureBuffer encode(const Group& group) {
  return encoded([&](SecureWriter& writer) {
    writer.string(group.name);
    writer.string(group.description);
    write_posix(writer, group.posix_number);
    writer.u64(group.created);
    writer.u64(group.updated);
  });
}

std::optional<Group> decode_group(std::span<const unsigned char> value) {
  return decode_whole<Group>(value, [](dannan::net::Reader& reader) -> std::optional<Group> {
    const auto format = reader.u8();
    if (format != kFormat1 && format != kFormat) return std::nullopt;
    Group group;
    group.name = reader.string(kMostFieldBytes);
    group.description = reader.string(kMostFieldBytes);
    if (format == kFormat) {
      const auto posix = read_posix(reader);
      if (!posix) return std::nullopt;
      group.posix_number = *posix;
    }
    group.created = reader.u64();
    group.updated = reader.u64();
    return group;
  });
}

SecureBuffer encode(const Membership& membership) {
  return encoded([&](SecureWriter& writer) {
    writer.string(membership.group_id);
    writer.string(membership.user_id);
    writer.u64(membership.added);
  });
}

std::optional<Membership> decode_membership(std::span<const unsigned char> value) {
  return decode_whole<Membership>(value, [](dannan::net::Reader& reader) -> std::optional<Membership> {
    if (reader.u8() != kFormat) return std::nullopt;
    Membership membership;
    membership.group_id = reader.string(kMostFieldBytes);
    membership.user_id = reader.string(kMostFieldBytes);
    membership.added = reader.u64();
    return membership;
  });
}

std::vector<store::TableSpec> table_specs() {
  // An index answers nothing for a value it cannot read: the store then holds the record
  // unindexed rather than refusing to open over it.
  store::IndexSpec user_name{"name", [](std::span<const unsigned char> value) {
                               const auto user = decode_user(value);
                               return user ? std::vector<std::string>{user->name} : std::vector<std::string>{};
                             }};
  store::IndexSpec user_email{"email", [](std::span<const unsigned char> value) {
                                const auto user = decode_user(value);
                                return user && !user->email.empty() ? std::vector<std::string>{user->email} : std::vector<std::string>{};
                              }};
  store::IndexSpec group_name{"name", [](std::span<const unsigned char> value) {
                                const auto group = decode_group(value);
                                return group ? std::vector<std::string>{group->name} : std::vector<std::string>{};
                              }};
  return {
      store::TableSpec{kUsers, {user_name, user_email}},
      store::TableSpec{kGroups, {group_name}},
      store::TableSpec{kMemberships, {}},
  };
}

}  // namespace lugh::directory

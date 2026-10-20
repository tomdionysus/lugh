#include "directory/records.h"

#include "core/byte_io.h"

namespace lugh::directory {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::uint8_t kEnrolled = 0x01;
constexpr std::uint8_t kDisabled = 0x02;

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
SecureBytes encoded(Write write) {
  SecureBytes out;
  ByteWriter<SecureBytes> writer(out);
  writer.u8(kFormat);
  write(writer);
  return out;
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

SecureBytes encode(const User& user) {
  return encoded([&](ByteWriter<SecureBytes>& writer) {
    writer.u8(static_cast<std::uint8_t>(user.kind));
    writer.u8(static_cast<std::uint8_t>((user.enrolled ? kEnrolled : 0) | (user.disabled ? kDisabled : 0)));
    writer.field(user.name);
    writer.field(user.email);
    writer.field(user.display_name);
    writer.u64(user.created);
    writer.u64(user.updated);
  });
}

std::optional<User> decode_user(std::span<const unsigned char> value) {
  ByteReader reader(value);
  const auto format = reader.u8();
  const auto kind = reader.u8();
  const auto flags = reader.u8();
  auto name = reader.field();
  auto email = reader.field();
  auto display = reader.field();
  const auto created = reader.u64();
  const auto updated = reader.u64();
  if (!format || *format != kFormat || !kind || !flags || !name || !email || !display || !created || !updated || !reader.done()) return std::nullopt;
  if (*kind != static_cast<std::uint8_t>(Kind::person) && *kind != static_cast<std::uint8_t>(Kind::service)) return std::nullopt;
  if ((*flags & ~(kEnrolled | kDisabled)) != 0) return std::nullopt;

  User user;
  user.kind = static_cast<Kind>(*kind);
  user.enrolled = (*flags & kEnrolled) != 0;
  user.disabled = (*flags & kDisabled) != 0;
  user.name = std::move(*name);
  user.email = std::move(*email);
  user.display_name = std::move(*display);
  user.created = *created;
  user.updated = *updated;
  return user;
}

SecureBytes encode(const Group& group) {
  return encoded([&](ByteWriter<SecureBytes>& writer) {
    writer.field(group.name);
    writer.field(group.description);
    writer.u64(group.created);
    writer.u64(group.updated);
  });
}

std::optional<Group> decode_group(std::span<const unsigned char> value) {
  ByteReader reader(value);
  const auto format = reader.u8();
  auto name = reader.field();
  auto description = reader.field();
  const auto created = reader.u64();
  const auto updated = reader.u64();
  if (!format || *format != kFormat || !name || !description || !created || !updated || !reader.done()) return std::nullopt;

  Group group;
  group.name = std::move(*name);
  group.description = std::move(*description);
  group.created = *created;
  group.updated = *updated;
  return group;
}

SecureBytes encode(const Membership& membership) {
  return encoded([&](ByteWriter<SecureBytes>& writer) {
    writer.field(membership.group_id);
    writer.field(membership.user_id);
    writer.u64(membership.added);
  });
}

std::optional<Membership> decode_membership(std::span<const unsigned char> value) {
  ByteReader reader(value);
  const auto format = reader.u8();
  auto group = reader.field();
  auto user = reader.field();
  const auto added = reader.u64();
  if (!format || *format != kFormat || !group || !user || !added || !reader.done()) return std::nullopt;

  Membership membership;
  membership.group_id = std::move(*group);
  membership.user_id = std::move(*user);
  membership.added = *added;
  return membership;
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

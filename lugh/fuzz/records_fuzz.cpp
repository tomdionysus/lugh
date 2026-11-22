//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The directory's, authn's, the applications' and the scope grants' record parsers: users,
// groups, memberships, TOTP factors, recovery codes, enrolment links, audit entries,
// applications and the scopes each group grants. Each reads a value the store has
// opened, so it is reached only with the keys, but a parser that trusts its input is one
// bad record from a crash at start. Also the text a person types: base32, names,
// addresses, recovery codes. The first byte picks which, so one corpus covers all.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include "lugh/apps/app.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/enrolment_links.h"
#include "lugh/authn/factors.h"
#include "lugh/core/encoding.h"
#include "lugh/directory/records.h"
#include "lugh/fuzz/target.h"
#include "lugh/scopes/grants.h"

namespace {

// What parses must say the same when written again.
template <typename Encoded>
void same(const Encoded& again, std::span<const unsigned char> input) {
  if (again.size() != input.size() || !std::equal(again.begin(), again.end(), input.begin()))
    lugh::fuzz::finding("a record that does not write back as itself");
}

// A user or group in format 1, which is still read and never written: it is written in the
// current format, so the bytes differ by design. What it says must survive instead: rewritten,
// read and rewritten again, it is the same (fuzz_records, 2026-11-16).
template <typename Record, typename Decode>
void same_or_upgraded(const Record& record, std::span<const unsigned char> input, Decode decode) {
  const auto written = lugh::directory::encode(record);
  if (input.empty() || input[0] != 1) return same(written, input);
  const auto read = decode(std::span<const unsigned char>(written.data(), written.size()));
  if (!read) lugh::fuzz::finding("a record upgraded from format 1 that does not read again");
  same(lugh::directory::encode(*read), std::span<const unsigned char>(written.data(), written.size()));
}

int run(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::span<const unsigned char> input(data + 1, size - 1);
  const std::string_view text(reinterpret_cast<const char*>(input.data()), input.size());

  using namespace lugh;
  switch (data[0] % 11) {
    case 0:
      if (const auto user = directory::decode_user(input)) same_or_upgraded(*user, input, directory::decode_user);
      break;
    case 1:
      if (const auto group = directory::decode_group(input)) same_or_upgraded(*group, input, directory::decode_group);
      break;
    case 2:
      if (const auto membership = directory::decode_membership(input)) same(directory::encode(*membership), input);
      break;
    case 3:
      if (const auto totp = authn::decode_totp(input)) same(authn::encode(*totp), input);
      if (const auto credential = authn::decode_webauthn(input)) same(authn::encode(*credential), input);
      break;
    case 4:
      if (const auto recovery = authn::decode_recovery(input)) same(authn::encode(*recovery), input);
      break;
    case 5:
      if (const auto link = authn::EnrolmentLinks::decode(input)) same(authn::EnrolmentLinks::encode(*link), input);
      break;
    case 6:
      if (const auto entry = audit::AuditLog::decode(input)) same(audit::AuditLog::encode(*entry), input);
      break;
    case 8:
      if (const auto app = apps::decode(input)) same(apps::encode(*app), input);
      break;
    case 9:
      if (const auto granted = scopes::Grants::decode(input)) same(scopes::Grants::encode(*granted), input);
      break;
    case 7:
      if (const auto decoded = encoding::base32_decode(text)) {
        auto upper = std::string(text);
        for (auto& c : upper) c = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
        if (encoding::base32(*decoded) != upper) fuzz::finding("base32 that does not write back as itself, upper case");
      }
      break;
    default:
      if (const auto name = directory::normal_name(text); name && directory::normal_name(*name) != name) fuzz::finding("a name not yet normal once normalised");
      if (const auto email = directory::normal_email(text); email && directory::normal_email(*email) != email)
        fuzz::finding("an address not yet normal once normalised");
      (void)directory::printable(text, 1024);
      (void)authn::normal_recovery_code(text);
      break;
  }
  return 0;
}

// One seed per parser, each a value of its type written by its own encoder after the byte that
// picks it, and the text cases' own words.
template <typename Decode, typename Encode>
lugh::fuzz::Bytes written(unsigned char selector, Decode decode, Encode encode) {
  using Value = std::remove_cvref_t<decltype(*decode(std::span<const unsigned char>()))>;
  return lugh::fuzz::selected(selector, encode(Value{}));
}

std::vector<lugh::fuzz::Bytes> seeds() {
  using namespace lugh;
  const auto text = [](unsigned char selector, std::string_view words) { return fuzz::selected(selector, words); };
  return {
      written(0, directory::decode_user, [](const auto& v) { return directory::encode(v); }),
      written(1, directory::decode_group, [](const auto& v) { return directory::encode(v); }),
      written(2, directory::decode_membership, [](const auto& v) { return directory::encode(v); }),
      written(3, authn::decode_totp, [](const auto& v) { return authn::encode(v); }),
      written(3, authn::decode_webauthn, [](const auto& v) { return authn::encode(v); }),
      written(4, authn::decode_recovery, [](const auto& v) { return authn::encode(v); }),
      written(5, authn::EnrolmentLinks::decode, [](const auto& v) { return authn::EnrolmentLinks::encode(v); }),
      written(6, audit::AuditLog::decode, [](const auto& v) { return audit::AuditLog::encode(v); }),
      text(7, "MZXW6YTBOI"),
      written(8, apps::decode, [](const auto& v) { return apps::encode(v); }),
      written(9, scopes::Grants::decode, [](const auto& v) { return scopes::Grants::encode(v); }),
      text(10, "alice.smith"),
      text(10, "Alice@Example.COM"),
  };
}

const dannan::fuzz::Registration registered("records", [](std::span<const std::uint8_t> input) { run(input.data(), input.size()); }, seeds);

}  // namespace

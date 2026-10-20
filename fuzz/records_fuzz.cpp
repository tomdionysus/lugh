// The directory's and authn's record parsers: users, groups, memberships, TOTP factors,
// recovery codes, enrolment links and audit entries. Each reads a value the store has
// opened, so it is reached only with the keys, but a parser that trusts its input is one
// bad record from a crash at start. Also the text a person types: base32, names,
// addresses, recovery codes. The first byte picks which, so one corpus covers all.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "audit/audit_log.h"
#include "authn/enrolment_links.h"
#include "authn/factors.h"
#include "core/encoding.h"
#include "directory/records.h"

namespace {

// What parses must say the same when written again.
template <typename Encoded>
void same(const Encoded& again, std::span<const unsigned char> input) {
  if (again.size() != input.size() || !std::equal(again.begin(), again.end(), input.begin())) __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::span<const unsigned char> input(data + 1, size - 1);
  const std::string_view text(reinterpret_cast<const char*>(input.data()), input.size());

  using namespace lugh;
  switch (data[0] % 9) {
    case 0:
      if (const auto user = directory::decode_user(input)) same(directory::encode(*user), input);
      break;
    case 1:
      if (const auto group = directory::decode_group(input)) same(directory::encode(*group), input);
      break;
    case 2:
      if (const auto membership = directory::decode_membership(input)) same(directory::encode(*membership), input);
      break;
    case 3:
      if (const auto totp = authn::decode_totp(input)) same(authn::encode(*totp), input);
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
    case 7:
      if (const auto decoded = encoding::base32_decode(text)) {
        auto upper = std::string(text);
        for (auto& c : upper) c = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
        if (encoding::base32(*decoded) != upper) __builtin_trap();
      }
      break;
    default:
      if (const auto name = directory::normal_name(text); name && directory::normal_name(*name) != name) __builtin_trap();
      if (const auto email = directory::normal_email(text); email && directory::normal_email(*email) != email) __builtin_trap();
      (void)directory::printable(text, 1024);
      (void)authn::normal_recovery_code(text);
      break;
  }
  return 0;
}

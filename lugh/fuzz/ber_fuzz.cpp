//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What the LDAP listener reads before anyone is bound: the framing, and a whole message.

#include <cstddef>
#include <cstdint>
#include <span>

#include "lugh/ldap/ber.h"
#include "lugh/ldap/messages.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::ldap;
  const std::span<const unsigned char> bytes(data, size);
  const auto framed = ber::frame(bytes, kMostMessageBytes);
  if (framed.state == ber::Frame::State::complete && framed.size > size) __builtin_trap();

  if (const auto message = parse_message(bytes)) {
    if (message->id <= 0) __builtin_trap();
    for (const auto& control : message->controls) {
      if (control.value) {
        (void)parse_paged_results(*control.value);
        (void)parse_password_modify(*control.value);
      }
    }
    if (const auto* extended = std::get_if<ExtendedRequest>(&message->request); extended && extended->value) (void)parse_password_modify(*extended->value);
  }
  return 0;
}

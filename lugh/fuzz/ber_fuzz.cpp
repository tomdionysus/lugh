//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What the LDAP listener reads before anyone is bound: the framing, and a whole message.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/fuzz/target.h"
#include "lugh/ldap/ber.h"
#include "lugh/ldap/messages.h"

namespace {

int run(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::ldap;
  const std::span<const unsigned char> bytes(data, size);
  const auto framed = ber::frame(bytes, kMostMessageBytes);
  if (framed.state == ber::Frame::State::complete && framed.size > size) lugh::fuzz::finding("a complete frame longer than its input");

  if (const auto message = parse_message(bytes)) {
    if (message->id <= 0) lugh::fuzz::finding("a message id that is not positive");
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

const dannan::fuzz::Registration registered(
    "ber", [](std::span<const std::uint8_t> input) { run(input.data(), input.size()); }, [] { return lugh::fuzz::corpus("ber"); });

}  // namespace

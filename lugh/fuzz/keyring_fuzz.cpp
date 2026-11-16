//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The keyring's two parsers: the header, read before anything is decrypted and so open to
// whoever can write the file, and the body, read after. The first byte picks which, so one
// corpus covers both.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/keys/keyring_format.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::span<const unsigned char> input(data + 1, size - 1);

  if (data[0] & 1) {
    const auto parsed = lugh::keys::decode_header(input);
    // What parses must say the same when written again.
    if (parsed) {
      const auto again = lugh::keys::encode_header(parsed->header);
      if (again.size() != parsed->length || !std::equal(again.begin(), again.end(), input.begin())) std::abort();
    }
  } else {
    const auto keys = lugh::keys::decode_body(input);
    if (keys) {
      const auto again = lugh::keys::encode_body(*keys);
      if (again.size() != input.size() || !std::equal(again.begin(), again.end(), input.begin())) std::abort();
    }
  }
  return 0;
}

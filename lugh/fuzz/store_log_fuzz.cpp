//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A table's log as it is read at open: the header parse, the frame scan, and the
// torn-or-damaged decision, over whatever is on the disk. The key is fixed, so most frames
// fail to open; the header and framing are what is under test.

#include <cstddef>
#include <cstdint>
#include <span>

#include "lugh/store/log_format.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const lugh::SecureBuffer key(32, 0x42);
  const auto key_for = [](std::uint32_t epoch) -> const lugh::SecureBuffer* { return epoch == 1 ? &key : nullptr; };

  const std::span<const unsigned char> file(data, size);
  (void)lugh::store::decode_file_header(file);
  const auto scan = lugh::store::scan_log(file, "users", key_for);
  if (scan.ok && scan.value.valid_length > size) __builtin_trap();
  return 0;
}

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lugh::signin {

// A QR symbol (ISO/IEC 18004): `size` modules a side, `dark` row by row. Byte mode, error
// correction level M, the smallest version that holds the text.
struct QrCode {
  int version = 0;
  int size = 0;
  int mask = 0;
  std::vector<bool> dark;

  bool at(int x, int y) const { return dark[static_cast<std::size_t>(y) * size + x]; }
};

// The symbol for `text`; nothing for more than the largest version holds (2331 bytes).
std::optional<QrCode> qr_encode(std::string_view text);

// The symbol as an inline SVG, dark on white with the four-module quiet zone a reader needs,
// labelled `label` (text, escaped here). No script and no style attribute, so it passes the
// pages' policy.
std::string qr_svg(const QrCode& code, std::string_view label);

}  // namespace lugh::signin

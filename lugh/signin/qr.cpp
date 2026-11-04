//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/signin/qr.h"

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstdlib>

#include "lugh/signin/html.h"

namespace lugh::signin {

namespace {

constexpr int kLowestVersion = 1;
constexpr int kHighestVersion = 40;
constexpr int kQuietZone = 4;

// Table 9 of the standard, level M, by version: error correction codewords per block, and blocks.
constexpr std::array<int, 41> kEccPerBlock = {0,  10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
                                              26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28};
constexpr std::array<int, 41> kBlocks = {0,  1,  1,  1,  2,  2,  4,  4,  4,  5,  5,  5,  8,  9,  9,  10, 10, 11, 13, 14, 16,
                                         17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49};

// Level M's indicator in the format information.
constexpr int kLevelM = 0;

// The modules a version has for codewords, once the fixed patterns have theirs.
int data_modules(int version) {
  int out = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const int aligns = version / 7 + 2;
    out -= (25 * aligns - 10) * aligns - 55;
    if (version >= 7) out -= 36;
  }
  return out;
}

int data_codewords(int version) { return data_modules(version) / 8 - kEccPerBlock[version] * kBlocks[version]; }

// Multiplication in GF(2^8) under the standard's polynomial, x^8 + x^4 + x^3 + x^2 + 1.
std::uint8_t gf_multiply(std::uint8_t a, std::uint8_t b) {
  int out = 0;
  for (int bit = 7; bit >= 0; --bit) {
    out = (out << 1) ^ ((out >> 7) * 0x11D);
    out ^= ((b >> bit) & 1) * a;
  }
  return static_cast<std::uint8_t>(out);
}

std::vector<std::uint8_t> rs_divisor(int degree) {
  std::vector<std::uint8_t> out(static_cast<std::size_t>(degree), 0);
  out.back() = 1;
  std::uint8_t root = 1;
  for (int i = 0; i < degree; ++i) {
    for (std::size_t j = 0; j < out.size(); ++j) {
      out[j] = gf_multiply(out[j], root);
      if (j + 1 < out.size()) out[j] ^= out[j + 1];
    }
    root = gf_multiply(root, 2);
  }
  return out;
}

std::vector<std::uint8_t> rs_remainder(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& divisor) {
  std::vector<std::uint8_t> out(divisor.size(), 0);
  for (const auto byte : data) {
    const auto factor = static_cast<std::uint8_t>(byte ^ out.front());
    out.erase(out.begin());
    out.push_back(0);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] ^= gf_multiply(divisor[i], factor);
  }
  return out;
}

// The message: mode, length, the bytes, terminator and padding, as data codewords.
std::vector<std::uint8_t> message_of(std::string_view text, int version) {
  const int capacity = data_codewords(version);
  std::vector<bool> bits;
  const auto append = [&](unsigned value, int count) {
    for (int bit = count - 1; bit >= 0; --bit) bits.push_back(((value >> bit) & 1) != 0);
  };
  append(0b0100, 4);
  append(static_cast<unsigned>(text.size()), version <= 9 ? 8 : 16);
  for (const unsigned char byte : text) append(byte, 8);
  append(0, std::min(4, capacity * 8 - static_cast<int>(bits.size())));
  while (bits.size() % 8 != 0) bits.push_back(false);
  std::vector<std::uint8_t> out(bits.size() / 8, 0);
  for (std::size_t i = 0; i < bits.size(); ++i) {
    if (bits[i]) out[i / 8] |= static_cast<std::uint8_t>(0x80 >> (i % 8));
  }
  for (std::uint8_t pad = 0xEC; static_cast<int>(out.size()) < capacity; pad ^= 0xEC ^ 0x11) out.push_back(pad);
  return out;
}

// The codewords in the order they are placed: the data blocks interleaved, then their error
// correction interleaved. The first blocks are a codeword shorter when they do not divide evenly.
std::vector<std::uint8_t> interleaved(const std::vector<std::uint8_t>& message, int version) {
  const int blocks = kBlocks[version];
  const int ecc = kEccPerBlock[version];
  const int total = data_modules(version) / 8;
  const int short_blocks = blocks - total % blocks;
  const int short_data = total / blocks - ecc;
  const auto divisor = rs_divisor(ecc);

  std::vector<std::vector<std::uint8_t>> data;
  std::vector<std::vector<std::uint8_t>> corrections;
  auto from = message.begin();
  for (int i = 0; i < blocks; ++i) {
    const int length = short_data + (i < short_blocks ? 0 : 1);
    data.emplace_back(from, from + length);
    from += length;
    corrections.push_back(rs_remainder(data.back(), divisor));
  }
  std::vector<std::uint8_t> out;
  out.reserve(static_cast<std::size_t>(total));
  for (int i = 0; i <= short_data; ++i) {
    for (int block = 0; block < blocks; ++block) {
      if (i < static_cast<int>(data[block].size())) out.push_back(data[block][i]);
    }
  }
  for (int i = 0; i < ecc; ++i) {
    for (int block = 0; block < blocks; ++block) out.push_back(corrections[block][i]);
  }
  return out;
}

// A symbol being built: which modules are dark, and which belong to the fixed patterns.
class Matrix {
 public:
  explicit Matrix(int version_number) : version(version_number), size(version_number * 4 + 17), dark(area(), false), fixed(area(), false) {}

  void set(int x, int y, bool value) {
    dark[index(x, y)] = value;
    fixed[index(x, y)] = true;
  }

  void patterns() {
    for (int i = 0; i < size; ++i) {
      set(6, i, i % 2 == 0);
      set(i, 6, i % 2 == 0);
    }
    finder(3, 3);
    finder(size - 4, 3);
    finder(3, size - 4);
    if (version >= 2) {
      const auto centres = alignment_centres();
      const auto last = centres.size() - 1;
      for (std::size_t i = 0; i < centres.size(); ++i) {
        for (std::size_t j = 0; j < centres.size(); ++j) {
          // Those that would land on a finder are left out.
          if ((i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0)) continue;
          alignment(centres[i], centres[j]);
        }
      }
    }
    format(0);
    if (version >= 7) version_information();
  }

  // The format information: the level and the mask, protected by a BCH code, placed twice.
  void format(int mask) {
    const int message = (kLevelM << 3) | mask;
    int remainder = message;
    for (int i = 0; i < 10; ++i) remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537);
    const int bits = ((message << 10) | remainder) ^ 0x5412;
    const auto bit = [&](int i) { return ((bits >> i) & 1) != 0; };

    for (int i = 0; i <= 5; ++i) set(8, i, bit(i));
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for (int i = 9; i < 15; ++i) set(14 - i, 8, bit(i));

    for (int i = 0; i < 8; ++i) set(size - 1 - i, 8, bit(i));
    for (int i = 8; i < 15; ++i) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  }

  // The codewords along the two-wide zigzag, from the bottom right, skipping the timing column.
  void place(const std::vector<std::uint8_t>& codewords) {
    std::size_t at = 0;
    const std::size_t bits = codewords.size() * 8;
    for (int right = size - 1; right >= 1; right -= 2) {
      if (right == 6) right = 5;
      for (int step = 0; step < size; ++step) {
        const bool upward = ((right + 1) & 2) == 0;
        const int y = upward ? size - 1 - step : step;
        for (int column = 0; column < 2; ++column) {
          const int x = right - column;
          if (fixed[index(x, y)]) continue;
          if (at < bits) dark[index(x, y)] = ((codewords[at >> 3] >> (7 - (at & 7))) & 1) != 0;
          ++at;
        }
      }
    }
  }

  void apply_mask(int mask) {
    for (int y = 0; y < size; ++y) {
      for (int x = 0; x < size; ++x) {
        if (fixed[index(x, y)]) continue;
        bool invert = false;
        switch (mask) {
          case 0:
            invert = (x + y) % 2 == 0;
            break;
          case 1:
            invert = y % 2 == 0;
            break;
          case 2:
            invert = x % 3 == 0;
            break;
          case 3:
            invert = (x + y) % 3 == 0;
            break;
          case 4:
            invert = (x / 3 + y / 2) % 2 == 0;
            break;
          case 5:
            invert = x * y % 2 + x * y % 3 == 0;
            break;
          case 6:
            invert = (x * y % 2 + x * y % 3) % 2 == 0;
            break;
          default:
            invert = ((x + y) % 2 + x * y % 3) % 2 == 0;
            break;
        }
        if (invert) dark[index(x, y)] = !dark[index(x, y)];
      }
    }
  }

  // The standard's four penalties (section 7.8.3.1): the mask with the lowest is the one used.
  int penalty() const {
    int out = 0;
    const auto line = [&](auto module) {
      int run = 0;
      bool colour = false;
      unsigned window = 0;
      for (int i = 0; i < size; ++i) {
        const bool here = module(i);
        if (i > 0 && here == colour) {
          ++run;
          if (run == 5) out += 3;
          if (run > 5) ++out;
        } else {
          colour = here;
          run = 1;
        }
        window = ((window << 1) | (here ? 1u : 0u)) & 0x7FF;
        if (i >= 10 && (window == 0b10111010000 || window == 0b00001011101)) out += 40;
      }
    };
    for (int y = 0; y < size; ++y) line([&](int x) { return at(x, y); });
    for (int x = 0; x < size; ++x) line([&](int y) { return at(x, y); });
    for (int y = 0; y + 1 < size; ++y) {
      for (int x = 0; x + 1 < size; ++x) {
        const bool colour = at(x, y);
        if (colour == at(x + 1, y) && colour == at(x, y + 1) && colour == at(x + 1, y + 1)) out += 3;
      }
    }
    const auto dark_modules = std::count(dark.begin(), dark.end(), true);
    const auto total = static_cast<long>(size) * size;
    out += static_cast<int>(std::labs(dark_modules * 20 - total * 10) / total) * 10;
    return out;
  }

  bool at(int x, int y) const { return dark[index(x, y)]; }

  int version;
  int size;
  std::vector<bool> dark;
  std::vector<bool> fixed;

 private:
  std::size_t area() const { return static_cast<std::size_t>(size) * size; }
  std::size_t index(int x, int y) const { return static_cast<std::size_t>(y) * size + x; }

  void finder(int cx, int cy) {
    for (int dy = -4; dy <= 4; ++dy) {
      for (int dx = -4; dx <= 4; ++dx) {
        const int x = cx + dx;
        const int y = cy + dy;
        if (x < 0 || x >= size || y < 0 || y >= size) continue;
        const int ring = std::max(std::abs(dx), std::abs(dy));
        set(x, y, ring != 2 && ring != 4);
      }
    }
  }

  void alignment(int cx, int cy) {
    for (int dy = -2; dy <= 2; ++dy) {
      for (int dx = -2; dx <= 2; ++dx) set(cx + dx, cy + dy, std::max(std::abs(dx), std::abs(dy)) != 1);
    }
  }

  std::vector<int> alignment_centres() const {
    const int count = version / 7 + 2;
    const int step = version == 32 ? 26 : (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
    std::vector<int> out{6};
    for (int i = count - 1; i >= 1; --i) out.insert(out.begin() + 1, size - 7 - (count - 1 - i) * step);
    return out;
  }

  void version_information() {
    int remainder = version;
    for (int i = 0; i < 12; ++i) remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25);
    const int bits = (version << 12) | remainder;
    for (int i = 0; i < 18; ++i) {
      const bool bit = ((bits >> i) & 1) != 0;
      const int across = size - 11 + i % 3;
      const int down = i / 3;
      set(across, down, bit);
      set(down, across, bit);
    }
  }
};

}  // namespace

std::optional<QrCode> qr_encode(std::string_view text) {
  int version = kLowestVersion;
  for (;; ++version) {
    if (version > kHighestVersion) return std::nullopt;
    const std::size_t header_bits = 4 + (version <= 9 ? 8 : 16);
    if (header_bits + text.size() * 8 <= static_cast<std::size_t>(data_codewords(version)) * 8) break;
  }
  Matrix matrix(version);
  matrix.patterns();
  matrix.place(interleaved(message_of(text, version), version));

  int best_mask = 0;
  int lowest = INT_MAX;
  for (int mask = 0; mask < 8; ++mask) {
    matrix.apply_mask(mask);
    matrix.format(mask);
    const int score = matrix.penalty();
    if (score < lowest) {
      lowest = score;
      best_mask = mask;
    }
    matrix.apply_mask(mask);
  }
  matrix.apply_mask(best_mask);
  matrix.format(best_mask);

  QrCode out;
  out.version = version;
  out.size = matrix.size;
  out.mask = best_mask;
  out.dark = matrix.dark;
  return out;
}

std::string qr_svg(const QrCode& code, std::string_view label) {
  const auto side = std::to_string(code.size + kQuietZone * 2);
  std::string out = "<svg class=\"qr\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + side + " " + side + "\" role=\"img\" aria-label=\"" +
                    escape(label) + "\" shape-rendering=\"crispEdges\"><rect width=\"" + side + "\" height=\"" + side +
                    "\" fill=\"#fff\"/><path fill=\"#000\" d=\"";
  for (int y = 0; y < code.size; ++y) {
    for (int x = 0; x < code.size; ++x) {
      if (code.at(x, y)) out += "M" + std::to_string(x + kQuietZone) + " " + std::to_string(y + kQuietZone) + "h1v1h-1z";
    }
  }
  out += "\"/></svg>";
  return out;
}

}  // namespace lugh::signin

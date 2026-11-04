//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "lugh/signin/qr.h"

using lugh::signin::qr_encode;
using lugh::signin::QrCode;

namespace {

// A reader written from the standard apart from the encoder: it takes the format information from
// the symbol, removes the mask the symbol names, follows the zigzag, undoes the interleaving,
// checks every block's error correction by its syndromes, and reads the message. Tables are the
// standard's, level M, and written out again here so an error in the encoder's cannot hide.
class Reader {
 public:
  explicit Reader(const QrCode& code) : _code(code), _version((code.size - 17) / 4), _centres(centres()) {}

  std::optional<std::string> read() {
    if (!format()) return std::nullopt;
    const auto codewords = walk();
    if (static_cast<int>(codewords.size()) != _total()) return std::nullopt;
    const auto data = blocks(codewords);
    if (!data) return std::nullopt;
    return message(*data);
  }

  int mask() const { return _mask; }

 private:
  static int ecc_per_block(int version) {
    static const std::vector<int> table{0,  10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
                                        26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28};
    return table[version];
  }
  static int block_count(int version) {
    static const std::vector<int> table{0,  1,  1,  1,  2,  2,  4,  4,  4,  5,  5,  5,  8,  9,  9,  10, 10, 11, 13, 14, 16,
                                        17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49};
    return table[version];
  }

  // Annex E's centres, by the rule: the first is 6, the last size - 7, the rest evenly spaced on
  // even numbers, the difference rounding so the first gap takes the remainder.
  std::vector<int> centres() const {
    if (_version == 1) return {};
    const int count = _version / 7 + 2;
    const int last = _code.size - 7;
    std::vector<int> out(count);
    out[0] = 6;
    out[count - 1] = last;
    if (count > 2) {
      const int span = last - 6;
      int step = span / (count - 1);
      if (_version == 32) {
        step = 26;
      } else if (step % 2 != 0 || span % (count - 1) != 0) {
        step = (span / (count - 1) + 2) & ~1;
      }
      for (int i = count - 2; i >= 1; --i) out[i] = out[i + 1] - step;
    }
    return out;
  }

  bool is_function(int x, int y) const {
    const int size = _code.size;
    if (x == 6 || y == 6) return true;
    if (x <= 8 && y <= 8) return true;
    if (x >= size - 8 && y <= 8) return true;
    if (x <= 8 && y >= size - 8) return true;
    if (_version >= 7 && ((x >= size - 11 && x <= size - 9 && y <= 5) || (y >= size - 11 && y <= size - 9 && x <= 5))) return true;
    const auto& all = _centres;
    for (std::size_t i = 0; i < all.size(); ++i) {
      for (std::size_t j = 0; j < all.size(); ++j) {
        const auto last = all.size() - 1;
        if ((i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0)) continue;
        if (std::abs(x - all[j]) <= 2 && std::abs(y - all[i]) <= 2) return true;
      }
    }
    return false;
  }

  // The first copy, around the top-left finder, must say level M and agree with the second.
  bool format() {
    int first = 0;
    for (int i = 0; i <= 5; ++i) first |= (_code.at(8, i) ? 1 : 0) << i;
    first |= (_code.at(8, 7) ? 1 : 0) << 6;
    first |= (_code.at(8, 8) ? 1 : 0) << 7;
    first |= (_code.at(7, 8) ? 1 : 0) << 8;
    for (int i = 9; i < 15; ++i) first |= (_code.at(14 - i, 8) ? 1 : 0) << i;
    int second = 0;
    for (int i = 0; i < 8; ++i) second |= (_code.at(_code.size - 1 - i, 8) ? 1 : 0) << i;
    for (int i = 8; i < 15; ++i) second |= (_code.at(8, _code.size - 15 + i) ? 1 : 0) << i;
    if (first != second) return false;
    const int plain = first ^ 0x5412;
    int check = plain;
    for (int i = 14; i >= 10; --i) {
      if ((check >> i) & 1) check ^= 0x537 << (i - 10);
    }
    if (check != 0) return false;
    if ((plain >> 13) != 0) return false;
    _mask = (plain >> 10) & 7;
    return true;
  }

  bool masked(int x, int y) const {
    switch (_mask) {
      case 0:
        return (y + x) % 2 == 0;
      case 1:
        return y % 2 == 0;
      case 2:
        return x % 3 == 0;
      case 3:
        return (y + x) % 3 == 0;
      case 4:
        return (y / 2 + x / 3) % 2 == 0;
      case 5:
        return (y * x) % 2 + (y * x) % 3 == 0;
      case 6:
        return ((y * x) % 2 + (y * x) % 3) % 2 == 0;
      default:
        return ((y + x) % 2 + (y * x) % 3) % 2 == 0;
    }
  }

  std::vector<std::uint8_t> walk() const {
    std::vector<std::uint8_t> out;
    int bits = 0;
    int current = 0;
    bool upward = true;
    for (int right = _code.size - 1; right > 0; right -= 2) {
      if (right == 6) --right;
      for (int step = 0; step < _code.size; ++step) {
        const int y = upward ? _code.size - 1 - step : step;
        for (int x : {right, right - 1}) {
          if (is_function(x, y)) continue;
          current = (current << 1) | ((_code.at(x, y) != masked(x, y)) ? 1 : 0);
          if (++bits == 8) {
            out.push_back(static_cast<std::uint8_t>(current));
            bits = 0;
            current = 0;
          }
        }
      }
      upward = !upward;
    }
    return out;
  }

  int _total() const {
    int modules = (16 * _version + 128) * _version + 64;
    if (_version >= 2) {
      const int aligns = _version / 7 + 2;
      modules -= (25 * aligns - 10) * aligns - 55;
      if (_version >= 7) modules -= 36;
    }
    return modules / 8;
  }

  static std::uint8_t multiply(std::uint8_t a, std::uint8_t b) {
    std::uint8_t out = 0;
    while (b != 0) {
      if (b & 1) out ^= a;
      const bool high = (a & 0x80) != 0;
      a = static_cast<std::uint8_t>(a << 1);
      if (high) a ^= 0x1D;
      b >>= 1;
    }
    return out;
  }

  // Each block read back, its data returned once all its syndromes are zero.
  std::optional<std::vector<std::uint8_t>> blocks(const std::vector<std::uint8_t>& codewords) const {
    const int count = block_count(_version);
    const int ecc = ecc_per_block(_version);
    const int total = _total();
    const int short_blocks = count - total % count;
    const int short_length = total / count - ecc;
    std::vector<std::vector<std::uint8_t>> split(count);
    std::size_t at = 0;
    for (int i = 0; i <= short_length; ++i) {
      for (int block = 0; block < count; ++block) {
        if (i < short_length || block >= short_blocks) split[block].push_back(codewords[at++]);
      }
    }
    for (int i = 0; i < ecc; ++i) {
      for (int block = 0; block < count; ++block) split[block].push_back(codewords[at++]);
    }
    std::vector<std::uint8_t> out;
    for (int block = 0; block < count; ++block) {
      std::uint8_t root = 1;
      for (int s = 0; s < ecc; ++s) {
        std::uint8_t value = 0;
        for (const auto byte : split[block]) value = multiply(value, root) ^ byte;
        if (value != 0) return std::nullopt;
        root = multiply(root, 2);
      }
      out.insert(out.end(), split[block].begin(), split[block].end() - ecc);
    }
    return out;
  }

  std::optional<std::string> message(const std::vector<std::uint8_t>& data) const {
    std::size_t bit = 0;
    const auto take = [&](int count) {
      unsigned out = 0;
      for (int i = 0; i < count; ++i, ++bit) out = (out << 1) | ((data[bit / 8] >> (7 - bit % 8)) & 1u);
      return out;
    };
    if (take(4) != 0b0100) return std::nullopt;
    const auto length = take(_version <= 9 ? 8 : 16);
    if (bit + length * 8 > data.size() * 8) return std::nullopt;
    std::string out;
    for (unsigned i = 0; i < length; ++i) out.push_back(static_cast<char>(take(8)));
    return out;
  }

  const QrCode& _code;
  int _version;
  std::vector<int> _centres;
  int _mask = -1;
};

std::string read_back(const std::string& text) {
  const auto code = qr_encode(text);
  EXPECT_TRUE(code) << text.size();
  if (!code) return {};
  Reader reader(*code);
  const auto read = reader.read();
  EXPECT_TRUE(read) << "version " << code->version;
  EXPECT_EQ(reader.mask(), code->mask);
  return read.value_or("");
}

}  // namespace

// Every size of symbol, across every block layout, is read back whole.
TEST(Qr, EveryVersionReadsBack) {
  const std::vector<int> capacities{14,  26,  42,  62,  84,  106,  122,  152,  180,  213,  251,  287,  331,  362,  412,  450,  504,  560,  624,  666,
                                    711, 779, 857, 911, 997, 1059, 1125, 1190, 1264, 1370, 1452, 1538, 1628, 1722, 1809, 1911, 1989, 2099, 2213, 2331};
  for (int version = 1; version <= 40; ++version) {
    std::string text;
    const int capacity = capacities[version - 1];
    for (int i = 0; i < capacity; ++i) text.push_back(static_cast<char>('a' + (i * 7 + version) % 26));
    const auto code = qr_encode(text);
    ASSERT_TRUE(code) << version;
    EXPECT_EQ(code->version, version) << "the standard's capacity for version " << version << " is " << capacity;
    EXPECT_EQ(code->size, version * 4 + 17);
    EXPECT_EQ(read_back(text), text) << version;
    // One byte more needs the next version.
    if (version < 40) EXPECT_EQ(qr_encode(text + "x")->version, version + 1) << version;
  }
}

TEST(Qr, TooLongIsNothing) {
  EXPECT_TRUE(qr_encode(std::string(2331, 'a')));
  EXPECT_FALSE(qr_encode(std::string(2332, 'a')));
}

// The shape of the bytes does not matter, and every mask is reachable by some text.
TEST(Qr, BytesOfEveryKindAndEveryMask) {
  std::string every;
  for (int i = 0; i < 256; ++i) every.push_back(static_cast<char>(i));
  EXPECT_EQ(read_back(every), every);
  EXPECT_EQ(read_back(""), "");

  // A fixed sequence, so this reads the same symbols every time, until each mask has been read.
  std::vector<bool> seen(8, false);
  std::uint32_t state = 1;
  int left = 8;
  for (int i = 0; i < 20000 && left > 0; ++i) {
    std::string text;
    for (int length = 0; length < 40; ++length) {
      state = state * 1664525u + 1013904223u;
      text.push_back(static_cast<char>(state >> 24));
    }
    const auto mask = qr_encode(text)->mask;
    if (seen[mask]) continue;
    seen[mask] = true;
    --left;
    EXPECT_EQ(read_back(text), text) << "mask " << mask;
  }
  EXPECT_EQ(left, 0);
}

// The fixed patterns, as the standard draws them.
TEST(Qr, TheFixedPatterns) {
  const auto code = qr_encode("otpauth://totp/Lugh:alice?secret=JBSWY3DPEHPK3PXP&issuer=Lugh&algorithm=SHA1&digits=6&period=30");
  ASSERT_TRUE(code);
  const auto finder = [&](int left, int top) {
    for (int y = 0; y < 7; ++y) {
      for (int x = 0; x < 7; ++x) {
        const bool ring = x == 0 || x == 6 || y == 0 || y == 6;
        const bool core = x >= 2 && x <= 4 && y >= 2 && y <= 4;
        EXPECT_EQ(code->at(left + x, top + y), ring || core) << left << "," << top << " at " << x << "," << y;
      }
    }
  };
  finder(0, 0);
  finder(code->size - 7, 0);
  finder(0, code->size - 7);
  // The separators, light.
  for (int i = 0; i < 8; ++i) {
    EXPECT_FALSE(code->at(7, i));
    EXPECT_FALSE(code->at(i, 7));
  }
  // The timing lines alternate.
  for (int i = 8; i < code->size - 8; ++i) {
    EXPECT_EQ(code->at(i, 6), i % 2 == 0);
    EXPECT_EQ(code->at(6, i), i % 2 == 0);
  }
  // The module that is always dark.
  EXPECT_TRUE(code->at(8, code->size - 8));
}

// The version information of version 7, worked in Annex D: 000111110010010100.
TEST(Qr, TheVersionInformation) {
  const auto code = qr_encode(std::string(122, 'a'));
  ASSERT_TRUE(code);
  ASSERT_EQ(code->version, 7);
  const int expected = 0b000111110010010100;
  for (int i = 0; i < 18; ++i) {
    const bool bit = ((expected >> i) & 1) != 0;
    EXPECT_EQ(code->at(code->size - 11 + i % 3, i / 3), bit) << i;
    EXPECT_EQ(code->at(i / 3, code->size - 11 + i % 3), bit) << i;
  }
}

TEST(Qr, TheSvgIsSafeUnderThePagesPolicy) {
  const auto code = qr_encode("hello");
  ASSERT_TRUE(code);
  const auto svg = lugh::signin::qr_svg(*code, "a <label> & \"more\"");
  EXPECT_EQ(svg.rfind("<svg class=\"qr\"", 0), 0u);
  EXPECT_NE(svg.find("a &lt;label&gt; &amp;"), std::string::npos);
  EXPECT_EQ(svg.find("<label>"), std::string::npos);
  // default-src 'none', style-src 'self': neither a script nor a style attribute.
  EXPECT_EQ(svg.find("<script"), std::string::npos);
  EXPECT_EQ(svg.find("style="), std::string::npos);
  // The quiet zone: the first module drawn is at four, and the box is the symbol and eight more.
  EXPECT_NE(svg.find("viewBox=\"0 0 " + std::to_string(code->size + 8) + " " + std::to_string(code->size + 8) + "\""), std::string::npos);
  EXPECT_NE(svg.find("d=\"M4 4h1v1h-1z"), std::string::npos);
}

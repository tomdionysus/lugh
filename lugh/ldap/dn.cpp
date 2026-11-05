//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/dn.h"

#include <algorithm>

namespace lugh::ldap {

namespace {

bool alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(char c) { return c >= '0' && c <= '9'; }

int hex_value(char c) {
  if (digit(c)) return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Those RFC 4514 section 2.4 says are escaped wherever they appear.
bool special(char c) { return c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\'; }

// What may follow a backslash and stand for itself: the specials, a space, a '#' and an '='.
bool escapable(char c) { return special(c) || c == ' ' || c == '#' || c == '='; }

void skip_spaces(std::string_view text, std::size_t& at) {
  while (at < text.size() && text[at] == ' ') ++at;
}

// A type, up to its '='.
std::optional<std::string> parse_type(std::string_view text, std::size_t& at) {
  const auto start = at;
  if (at >= text.size() || !alpha(text[at])) return std::nullopt;
  while (at < text.size() && (alpha(text[at]) || digit(text[at]) || text[at] == '-')) ++at;
  auto type = fold(text.substr(start, at - start));
  skip_spaces(text, at);
  if (at >= text.size() || text[at] != '=') return std::nullopt;
  ++at;
  return type;
}

// A value, up to the next unescaped ',' or the end. Spaces round it that are not escaped are not
// part of it, as RFC 4514 section 3 tolerates of what older clients send.
std::optional<std::string> parse_value(std::string_view text, std::size_t& at) {
  skip_spaces(text, at);
  if (at < text.size() && text[at] == '#') return std::nullopt;
  std::string value;
  std::size_t kept = 0;
  while (at < text.size() && text[at] != ',') {
    const char c = text[at];
    if (c == '\0') return std::nullopt;
    if (c == '\\') {
      if (at + 1 >= text.size()) return std::nullopt;
      const char next = text[at + 1];
      if (escapable(next)) {
        value.push_back(next);
        at += 2;
      } else {
        if (at + 2 >= text.size()) return std::nullopt;
        const int high = hex_value(next);
        const int low = hex_value(text[at + 2]);
        if (high < 0 || low < 0) return std::nullopt;
        const auto byte = static_cast<char>(high * 16 + low);
        if (byte == '\0') return std::nullopt;
        value.push_back(byte);
        at += 3;
      }
      kept = value.size();
      continue;
    }
    if (special(c)) return std::nullopt;
    value.push_back(c);
    if (c != ' ') kept = value.size();
    ++at;
  }
  value.resize(kept);
  if (value.empty()) return std::nullopt;
  return value;
}

}  // namespace

std::string fold(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(), [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; });
  return out;
}

std::optional<Dn> parse_dn(std::string_view text) {
  Dn out;
  std::size_t at = 0;
  skip_spaces(text, at);
  if (at == text.size()) return out;
  for (;;) {
    if (out.rdns.size() == kMostDnComponents) return std::nullopt;
    skip_spaces(text, at);
    auto type = parse_type(text, at);
    if (!type) return std::nullopt;
    auto value = parse_value(text, at);
    if (!value) return std::nullopt;
    out.rdns.push_back({std::move(*type), std::move(*value)});
    if (at == text.size()) return out;
    ++at;  // past the ','
  }
}

std::string escape_dn_value(std::string_view value) {
  std::string out;
  for (std::size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    const bool edge_space = c == ' ' && (i == 0 || i + 1 == value.size());
    if (special(c) || edge_space || (c == '#' && i == 0)) out.push_back('\\');
    out.push_back(c);
  }
  return out;
}

std::string to_string(const Dn& dn) {
  std::string out;
  for (const auto& rdn : dn.rdns) {
    if (!out.empty()) out.push_back(',');
    out += rdn.type + "=" + escape_dn_value(rdn.value);
  }
  return out;
}

Dn normalised(const Dn& dn) {
  Dn out;
  out.rdns.reserve(dn.rdns.size());
  for (const auto& rdn : dn.rdns) out.rdns.push_back({rdn.type, fold(rdn.value)});
  return out;
}

bool within(const Dn& dn, const Dn& ancestor) {
  if (dn.rdns.size() < ancestor.rdns.size()) return false;
  return std::equal(ancestor.rdns.rbegin(), ancestor.rdns.rend(), dn.rdns.rbegin());
}

}  // namespace lugh::ldap

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/filter.h"

#include <algorithm>
#include <charconv>

#include "lugh/ldap/dn.h"

namespace lugh::ldap {

namespace {

constexpr std::uint8_t kAnd = 0xA0;
constexpr std::uint8_t kOr = 0xA1;
constexpr std::uint8_t kNot = 0xA2;
constexpr std::uint8_t kEquality = 0xA3;
constexpr std::uint8_t kSubstrings = 0xA4;
constexpr std::uint8_t kGreaterOrEqual = 0xA5;
constexpr std::uint8_t kLessOrEqual = 0xA6;
constexpr std::uint8_t kPresent = 0x87;
constexpr std::uint8_t kApproximate = 0xA8;
constexpr std::uint8_t kExtensible = 0xA9;
constexpr std::uint8_t kInitial = 0x80;
constexpr std::uint8_t kAny = 0x81;
constexpr std::uint8_t kFinal = 0x82;

bool numeric_attribute(std::string_view attribute) { return attribute == "uidnumber" || attribute == "gidnumber"; }
bool dn_attribute(std::string_view attribute) { return attribute == "member" || attribute == "memberof"; }

std::optional<long long> number_of(std::string_view text) {
  long long out = 0;
  const auto end = text.data() + text.size();
  const auto [at, error] = std::from_chars(text.data(), end, out);
  if (error != std::errc() || at != end) return std::nullopt;
  return out;
}

// Attribute value and assertion, read: `attributeDesc`, `assertionValue` as a SEQUENCE's content.
bool parse_assertion(const ber::Element& element, Filter& out) {
  ber::Reader reader(element.content);
  const auto attribute = reader.next();
  const auto value = reader.next();
  if (!attribute || !value || attribute->tag != ber::kOctetString || value->tag != ber::kOctetString || !reader.empty()) return false;
  if (attribute->content.empty()) return false;
  out.attribute = fold(attribute->text());
  out.value = std::string(value->text());
  return true;
}

bool parse_substrings(const ber::Element& element, Filter& out) {
  ber::Reader reader(element.content);
  const auto attribute = reader.next();
  const auto pieces = reader.next();
  if (!attribute || !pieces || attribute->tag != ber::kOctetString || pieces->tag != ber::kSequence || !reader.empty()) return false;
  if (attribute->content.empty()) return false;
  out.attribute = fold(attribute->text());
  ber::Reader each(pieces->content);
  bool first = true;
  bool any = false;
  while (!each.empty()) {
    const auto piece = each.next();
    if (!piece) return false;
    // RFC 4511: at most one initial, which comes first; at most one final, which comes last.
    if (piece->tag == kInitial) {
      if (!first) return false;
      out.initial = std::string(piece->text());
    } else if (piece->tag == kAny) {
      if (out.last) return false;
      out.any.emplace_back(piece->text());
    } else if (piece->tag == kFinal) {
      if (out.last) return false;
      out.last = std::string(piece->text());
    } else {
      return false;
    }
    first = false;
    any = true;
  }
  return any;
}

std::optional<Filter> parse(const ber::Element& element, int depth, std::size_t& items) {
  if (depth > kMostFilterDepth || ++items > kMostFilterItems) return std::nullopt;
  Filter out;
  switch (element.tag) {
    case kAnd:
    case kOr: {
      out.kind = element.tag == kAnd ? Filter::Kind::all_of : Filter::Kind::any_of;
      ber::Reader reader(element.content);
      while (!reader.empty()) {
        const auto child = reader.next();
        if (!child) return std::nullopt;
        auto parsed = parse(*child, depth + 1, items);
        if (!parsed) return std::nullopt;
        out.children.push_back(std::move(*parsed));
      }
      return out;
    }
    case kNot: {
      out.kind = Filter::Kind::negated;
      ber::Reader reader(element.content);
      const auto child = reader.next();
      if (!child || !reader.empty()) return std::nullopt;
      auto parsed = parse(*child, depth + 1, items);
      if (!parsed) return std::nullopt;
      out.children.push_back(std::move(*parsed));
      return out;
    }
    case kEquality:
    case kGreaterOrEqual:
    case kLessOrEqual:
    case kApproximate:
      out.kind = element.tag == kEquality         ? Filter::Kind::equal
                 : element.tag == kGreaterOrEqual ? Filter::Kind::greater_or_equal
                 : element.tag == kLessOrEqual    ? Filter::Kind::less_or_equal
                                                  : Filter::Kind::approximate;
      if (!parse_assertion(element, out)) return std::nullopt;
      return out;
    case kSubstrings:
      out.kind = Filter::Kind::substring;
      if (!parse_substrings(element, out)) return std::nullopt;
      return out;
    case kPresent:
      if (element.content.empty()) return std::nullopt;
      out.kind = Filter::Kind::present;
      out.attribute = fold(element.text());
      return out;
    case kExtensible:
      out.kind = Filter::Kind::unsupported;
      return out;
    default:
      return std::nullopt;
  }
}

// How one stored value and one assertion compare, by the attribute's matching rule.
bool values_equal(std::string_view attribute, std::string_view stored, std::string_view assertion) {
  if (numeric_attribute(attribute)) {
    const auto a = number_of(stored);
    const auto b = number_of(assertion);
    return a && b && *a == *b;
  }
  if (dn_attribute(attribute)) {
    const auto a = parse_dn(stored);
    const auto b = parse_dn(assertion);
    return a && b && normalised(*a) == normalised(*b);
  }
  return fold(stored) == fold(assertion);
}

bool substring_matches(const Filter& filter, const std::string& stored) {
  const auto text = fold(stored);
  std::size_t at = 0;
  if (filter.initial) {
    const auto wanted = fold(*filter.initial);
    if (text.rfind(wanted, 0) != 0) return false;
    at = wanted.size();
  }
  for (const auto& piece : filter.any) {
    const auto wanted = fold(piece);
    const auto found = text.find(wanted, at);
    if (found == std::string::npos) return false;
    at = found + wanted.size();
  }
  if (filter.last) {
    const auto wanted = fold(*filter.last);
    if (text.size() < at + wanted.size()) return false;
    return text.compare(text.size() - wanted.size(), wanted.size(), wanted) == 0;
  }
  return true;
}

}  // namespace

void Entry::add(std::string_view name, std::string value) { attributes[fold(name)].push_back(std::move(value)); }

std::optional<Filter> parse_filter(const ber::Element& element) {
  std::size_t items = 0;
  return parse(element, 1, items);
}

Match Filter::evaluate(const Entry& entry) const {
  switch (kind) {
    case Kind::all_of: {
      // Undefined unless some term is false, and an empty `and` is true (RFC 4526).
      bool undefined = false;
      for (const auto& child : children) {
        const auto result = child.evaluate(entry);
        if (result == Match::no) return Match::no;
        undefined = undefined || result == Match::undefined;
      }
      return undefined ? Match::undefined : Match::yes;
    }
    case Kind::any_of: {
      bool undefined = false;
      for (const auto& child : children) {
        const auto result = child.evaluate(entry);
        if (result == Match::yes) return Match::yes;
        undefined = undefined || result == Match::undefined;
      }
      return undefined ? Match::undefined : Match::no;
    }
    case Kind::negated: {
      const auto result = children.front().evaluate(entry);
      if (result == Match::undefined) return Match::undefined;
      return result == Match::yes ? Match::no : Match::yes;
    }
    case Kind::present:
      // RFC 4511: FALSE when absent, not Undefined, so (!(mail=*)) finds those without one.
      return entry.attributes.count(attribute) > 0 ? Match::yes : Match::no;
    case Kind::unsupported:
      return Match::undefined;
    default:
      break;
  }

  const auto found = entry.attributes.find(attribute);
  if (found == entry.attributes.end()) return Match::undefined;
  const auto& values = found->second;
  switch (kind) {
    case Kind::equal:
    case Kind::approximate:
      return std::any_of(values.begin(), values.end(), [&](const std::string& stored) { return values_equal(attribute, stored, value); }) ? Match::yes
                                                                                                                                          : Match::no;
    case Kind::substring:
      if (numeric_attribute(attribute) || dn_attribute(attribute)) return Match::undefined;
      return std::any_of(values.begin(), values.end(), [&](const std::string& stored) { return substring_matches(*this, stored); }) ? Match::yes : Match::no;
    case Kind::greater_or_equal:
    case Kind::less_or_equal: {
      if (!numeric_attribute(attribute)) return Match::undefined;
      const auto assertion = number_of(value);
      if (!assertion) return Match::undefined;
      for (const auto& stored : values) {
        const auto number = number_of(stored);
        if (number && (kind == Kind::greater_or_equal ? *number >= *assertion : *number <= *assertion)) return Match::yes;
      }
      return Match::no;
    }
    default:
      return Match::undefined;
  }
}

std::optional<std::string> pinned_value(const Filter& filter, std::string_view attribute) {
  if (filter.kind == Filter::Kind::equal && filter.attribute == attribute) return filter.value;
  if (filter.kind != Filter::Kind::all_of) return std::nullopt;
  for (const auto& child : filter.children) {
    if (child.kind == Filter::Kind::equal && child.attribute == attribute) return child.value;
  }
  return std::nullopt;
}

}  // namespace lugh::ldap

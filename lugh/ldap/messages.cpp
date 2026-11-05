//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/messages.h"

#include <limits>

namespace lugh::ldap {

namespace {

using ber::Element;
using ber::Reader;

constexpr std::uint8_t kBind = 0x60;
constexpr std::uint8_t kUnbind = 0x42;
constexpr std::uint8_t kSearch = 0x63;
constexpr std::uint8_t kSearchEntry = 0x64;
constexpr std::uint8_t kModify = 0x66;
constexpr std::uint8_t kAdd = 0x68;
constexpr std::uint8_t kDelete = 0x4A;
constexpr std::uint8_t kModifyDn = 0x6C;
constexpr std::uint8_t kCompare = 0x6E;
constexpr std::uint8_t kAbandon = 0x50;
constexpr std::uint8_t kExtended = 0x77;
constexpr std::uint8_t kExtendedResponse = 0x78;
constexpr std::uint8_t kControls = 0xA0;
constexpr std::uint8_t kSimple = 0x80;
constexpr std::uint8_t kSasl = 0xA3;
constexpr std::uint8_t kExtendedName = 0x80;
constexpr std::uint8_t kExtendedValue = 0x81;
constexpr std::uint8_t kResponseName = 0x8A;
constexpr std::uint8_t kResponseValue = 0x8B;
constexpr std::uint8_t kNewSuperior = 0x80;
constexpr std::uint8_t kPasswordUser = 0x80;
constexpr std::uint8_t kPasswordOld = 0x81;
constexpr std::uint8_t kPasswordNew = 0x82;

constexpr std::int64_t kMostInt = std::numeric_limits<std::int32_t>::max();

std::optional<std::string> text_of(Reader& reader) {
  const auto element = reader.next();
  if (!element || element->tag != ber::kOctetString) return std::nullopt;
  return std::string(element->text());
}

std::optional<std::int64_t> int_of(Reader& reader, std::uint8_t tag) {
  const auto element = reader.next();
  if (!element || element->tag != tag) return std::nullopt;
  return ber::integer(*element);
}

std::optional<bool> bool_of(Reader& reader) {
  const auto element = reader.next();
  if (!element || element->tag != ber::kBoolean) return std::nullopt;
  return ber::boolean(*element);
}

std::optional<Attribute> attribute_of(const Element& element) {
  if (element.tag != ber::kSequence) return std::nullopt;
  Reader reader(element.content);
  auto type = text_of(reader);
  const auto values = reader.next();
  if (!type || type->empty() || !values || values->tag != ber::kSet || !reader.empty()) return std::nullopt;
  Attribute out;
  out.type = std::move(*type);
  Reader each(values->content);
  while (!each.empty()) {
    auto value = text_of(each);
    if (!value) return std::nullopt;
    out.values.push_back(std::move(*value));
  }
  return out;
}

std::optional<Request> parse_bind(const Element& element) {
  Reader reader(element.content);
  const auto version = int_of(reader, ber::kInteger);
  auto name = text_of(reader);
  const auto authentication = reader.next();
  if (!version || !name || !authentication || !reader.empty()) return std::nullopt;
  BindRequest out;
  out.version = *version;
  out.name = std::move(*name);
  if (authentication->tag == kSimple) {
    out.password = text_secret(std::string(authentication->text()));
  } else if (authentication->tag != kSasl) {
    return std::nullopt;
  }
  return Request(std::move(out));
}

std::optional<Request> parse_search(const Element& element) {
  Reader reader(element.content);
  auto base = text_of(reader);
  const auto scope = int_of(reader, ber::kEnumerated);
  const auto deref = int_of(reader, ber::kEnumerated);
  const auto size_limit = int_of(reader, ber::kInteger);
  const auto time_limit = int_of(reader, ber::kInteger);
  const auto types_only = bool_of(reader);
  const auto filter = reader.next();
  const auto attributes = reader.next();
  if (!base || !scope || !deref || !size_limit || !time_limit || !types_only || !filter || !attributes || !reader.empty()) return std::nullopt;
  if (*scope < 0 || *scope > 2 || *deref < 0 || *deref > 3) return std::nullopt;
  if (*size_limit < 0 || *size_limit > kMostInt || *time_limit < 0 || *time_limit > kMostInt) return std::nullopt;
  if (attributes->tag != ber::kSequence) return std::nullopt;
  auto parsed = parse_filter(*filter);
  if (!parsed) return std::nullopt;
  SearchRequest out;
  out.base = std::move(*base);
  out.scope = static_cast<Scope>(*scope);
  out.size_limit = *size_limit;
  out.time_limit = *time_limit;
  out.types_only = *types_only;
  out.filter = std::move(*parsed);
  Reader each(attributes->content);
  while (!each.empty()) {
    auto attribute = text_of(each);
    if (!attribute) return std::nullopt;
    out.attributes.push_back(std::move(*attribute));
  }
  return Request(std::move(out));
}

std::optional<Request> parse_modify(const Element& element) {
  Reader reader(element.content);
  auto object = text_of(reader);
  const auto changes = reader.next();
  if (!object || !changes || changes->tag != ber::kSequence || !reader.empty()) return std::nullopt;
  ModifyRequest out;
  out.object = std::move(*object);
  Reader each(changes->content);
  while (!each.empty()) {
    const auto change = each.next();
    if (!change || change->tag != ber::kSequence) return std::nullopt;
    Reader parts(change->content);
    const auto operation = int_of(parts, ber::kEnumerated);
    const auto attribute = parts.next();
    if (!operation || *operation < 0 || *operation > 2 || !attribute || !parts.empty()) return std::nullopt;
    auto parsed = attribute_of(*attribute);
    if (!parsed) return std::nullopt;
    out.changes.push_back({static_cast<ModifyOperation>(*operation), std::move(*parsed)});
  }
  return Request(std::move(out));
}

std::optional<Request> parse_add(const Element& element) {
  Reader reader(element.content);
  auto entry = text_of(reader);
  const auto attributes = reader.next();
  if (!entry || !attributes || attributes->tag != ber::kSequence || !reader.empty()) return std::nullopt;
  AddRequest out;
  out.entry = std::move(*entry);
  Reader each(attributes->content);
  while (!each.empty()) {
    const auto attribute = each.next();
    if (!attribute) return std::nullopt;
    auto parsed = attribute_of(*attribute);
    if (!parsed) return std::nullopt;
    out.attributes.push_back(std::move(*parsed));
  }
  return Request(std::move(out));
}

std::optional<Request> parse_modify_dn(const Element& element) {
  Reader reader(element.content);
  auto entry = text_of(reader);
  auto new_rdn = text_of(reader);
  const auto delete_old = bool_of(reader);
  if (!entry || !new_rdn || !delete_old) return std::nullopt;
  ModifyDnRequest out;
  out.entry = std::move(*entry);
  out.new_rdn = std::move(*new_rdn);
  out.delete_old = *delete_old;
  if (!reader.empty()) {
    const auto superior = reader.next();
    if (!superior || superior->tag != kNewSuperior || !reader.empty()) return std::nullopt;
    out.new_superior = std::string(superior->text());
  }
  return Request(std::move(out));
}

std::optional<Request> parse_compare(const Element& element) {
  Reader reader(element.content);
  auto entry = text_of(reader);
  const auto assertion = reader.next();
  if (!entry || !assertion || assertion->tag != ber::kSequence || !reader.empty()) return std::nullopt;
  Reader parts(assertion->content);
  auto attribute = text_of(parts);
  auto value = text_of(parts);
  if (!attribute || attribute->empty() || !value || !parts.empty()) return std::nullopt;
  return Request(CompareRequest{std::move(*entry), std::move(*attribute), std::move(*value)});
}

std::optional<Request> parse_extended(const Element& element) {
  Reader reader(element.content);
  const auto name = reader.next();
  if (!name || name->tag != kExtendedName || name->content.empty()) return std::nullopt;
  ExtendedRequest out;
  out.oid = std::string(name->text());
  if (!reader.empty()) {
    const auto value = reader.next();
    if (!value || value->tag != kExtendedValue || !reader.empty()) return std::nullopt;
    out.value = std::string(value->text());
  }
  return Request(std::move(out));
}

std::optional<Request> parse_request(const Element& element) {
  switch (element.tag) {
    case kBind:
      return parse_bind(element);
    case kUnbind:
      if (!element.content.empty()) return std::nullopt;
      return Request(UnbindRequest{});
    case kSearch:
      return parse_search(element);
    case kModify:
      return parse_modify(element);
    case kAdd:
      return parse_add(element);
    case kDelete:
      return Request(DeleteRequest{std::string(element.text())});
    case kModifyDn:
      return parse_modify_dn(element);
    case kCompare:
      return parse_compare(element);
    case kAbandon: {
      const auto id = ber::integer(element);
      if (!id || *id < 0 || *id > kMostInt) return std::nullopt;
      return Request(AbandonRequest{*id});
    }
    case kExtended:
      return parse_extended(element);
    default:
      return std::nullopt;
  }
}

std::optional<std::vector<Control>> parse_controls(const Element& element) {
  std::vector<Control> out;
  Reader each(element.content);
  while (!each.empty()) {
    const auto control = each.next();
    if (!control || control->tag != ber::kSequence) return std::nullopt;
    Reader parts(control->content);
    auto oid = text_of(parts);
    if (!oid || oid->empty()) return std::nullopt;
    Control parsed;
    parsed.oid = std::move(*oid);
    if (parts.peek_tag() == ber::kBoolean) {
      const auto critical = bool_of(parts);
      if (!critical) return std::nullopt;
      parsed.critical = *critical;
    }
    if (!parts.empty()) {
      parsed.value = text_of(parts);
      if (!parsed.value || !parts.empty()) return std::nullopt;
    }
    out.push_back(std::move(parsed));
  }
  return out;
}

void write_result(ber::Writer& writer, const Result& result) {
  writer.integer(ber::kEnumerated, static_cast<int>(result.code));
  writer.octets(ber::kOctetString, result.matched);
  writer.octets(ber::kOctetString, result.message);
}

void write_controls(ber::Writer& writer, const std::vector<Control>& controls) {
  if (controls.empty()) return;
  writer.begin(kControls);
  for (const auto& control : controls) {
    writer.begin(ber::kSequence);
    writer.octets(ber::kOctetString, control.oid);
    if (control.critical) writer.boolean(ber::kBoolean, true);
    if (control.value) writer.octets(ber::kOctetString, *control.value);
    writer.end();
  }
  writer.end();
}

ber::Bytes bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

}  // namespace

std::optional<Message> parse_message(ber::Bytes bytes) {
  Reader outer(bytes);
  const auto message = outer.next();
  if (!message || message->tag != ber::kSequence || !outer.empty()) return std::nullopt;
  Reader reader(message->content);
  const auto id = int_of(reader, ber::kInteger);
  // RFC 4511 section 4.1.1.1: a request's id is never zero.
  if (!id || *id <= 0 || *id > kMostInt) return std::nullopt;
  const auto operation = reader.next();
  if (!operation) return std::nullopt;
  auto request = parse_request(*operation);
  if (!request) return std::nullopt;
  Message out{*id, std::move(*request), {}};
  if (!reader.empty()) {
    const auto controls = reader.next();
    if (!controls || controls->tag != kControls || !reader.empty()) return std::nullopt;
    auto parsed = parse_controls(*controls);
    if (!parsed) return std::nullopt;
    out.controls = std::move(*parsed);
  }
  return out;
}

std::optional<PagedResults> parse_paged_results(std::string_view value) {
  Reader outer(bytes_of(value));
  const auto sequence = outer.next();
  if (!sequence || sequence->tag != ber::kSequence || !outer.empty()) return std::nullopt;
  Reader reader(sequence->content);
  const auto size = int_of(reader, ber::kInteger);
  auto cookie = text_of(reader);
  if (!size || *size < 0 || *size > kMostInt || !cookie || !reader.empty()) return std::nullopt;
  return PagedResults{*size, std::move(*cookie)};
}

std::string encode_paged_results(const PagedResults& paged) {
  ber::Writer writer;
  writer.begin(ber::kSequence);
  writer.integer(ber::kInteger, paged.size);
  writer.octets(ber::kOctetString, paged.cookie);
  writer.end();
  return writer.bytes();
}

std::optional<PasswordModify> parse_password_modify(std::string_view value) {
  Reader outer(bytes_of(value));
  const auto sequence = outer.next();
  if (!sequence || sequence->tag != ber::kSequence || !outer.empty()) return std::nullopt;
  PasswordModify out;
  Reader reader(sequence->content);
  std::uint8_t previous = 0;
  while (!reader.empty()) {
    const auto part = reader.next();
    // Each once, in the order RFC 3062 gives them.
    if (!part || part->tag <= previous) return std::nullopt;
    previous = part->tag;
    if (part->tag == kPasswordUser) {
      out.user = std::string(part->text());
    } else if (part->tag == kPasswordOld) {
      out.old_password = text_secret(std::string(part->text()));
    } else if (part->tag == kPasswordNew) {
      out.new_password = text_secret(std::string(part->text()));
    } else {
      return std::nullopt;
    }
  }
  return out;
}

std::string encode_result(std::int64_t id, ResponseOp op, const Result& result, const std::vector<Control>& controls) {
  ber::Writer writer;
  writer.begin(ber::kSequence);
  writer.integer(ber::kInteger, id);
  writer.begin(static_cast<std::uint8_t>(op));
  write_result(writer, result);
  writer.end();
  write_controls(writer, controls);
  writer.end();
  return writer.bytes();
}

std::string encode_search_entry(std::int64_t id, std::string_view dn, const std::vector<Attribute>& attributes) {
  ber::Writer writer;
  writer.begin(ber::kSequence);
  writer.integer(ber::kInteger, id);
  writer.begin(kSearchEntry);
  writer.octets(ber::kOctetString, dn);
  writer.begin(ber::kSequence);
  for (const auto& attribute : attributes) {
    writer.begin(ber::kSequence);
    writer.octets(ber::kOctetString, attribute.type);
    writer.begin(ber::kSet);
    for (const auto& value : attribute.values) writer.octets(ber::kOctetString, value);
    writer.end();
    writer.end();
  }
  writer.end();
  writer.end();
  writer.end();
  return writer.bytes();
}

std::string encode_extended(std::int64_t id, const Result& result, const std::optional<std::string>& oid, const std::optional<std::string>& value) {
  ber::Writer writer;
  writer.begin(ber::kSequence);
  writer.integer(ber::kInteger, id);
  writer.begin(kExtendedResponse);
  write_result(writer, result);
  if (oid) writer.octets(kResponseName, *oid);
  if (value) writer.octets(kResponseValue, *value);
  writer.end();
  writer.end();
  return writer.bytes();
}

}  // namespace lugh::ldap

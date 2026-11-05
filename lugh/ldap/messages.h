//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "lugh/core/secret.h"
#include "lugh/ldap/ber.h"
#include "lugh/ldap/filter.h"

// LDAPMessage (RFC 4511 section 4): requests read, responses written. Nothing here decides anything.
namespace lugh::ldap {

inline constexpr const char* kStartTlsOid = "1.3.6.1.4.1.1466.20037";
inline constexpr const char* kWhoAmIOid = "1.3.6.1.4.1.4203.1.11.3";
inline constexpr const char* kPasswordModifyOid = "1.3.6.1.4.1.4203.1.11.1";
inline constexpr const char* kPagedResultsOid = "1.2.840.113556.1.4.319";
inline constexpr const char* kAssertionOid = "1.3.6.1.1.12";

// The most a message may be (TODO/2026-11-04-ldap.md, "Transport and limits").
inline constexpr std::size_t kMostMessageBytes = 64 * 1024;

// RFC 4511 appendix A, those Lugh answers.
enum class ResultCode : int {
  success = 0,
  operations_error = 1,
  protocol_error = 2,
  time_limit_exceeded = 3,
  size_limit_exceeded = 4,
  compare_false = 5,
  compare_true = 6,
  auth_method_not_supported = 7,
  unavailable_critical_extension = 12,
  confidentiality_required = 13,
  no_such_attribute = 16,
  constraint_violation = 19,
  no_such_object = 32,
  inappropriate_authentication = 48,
  invalid_credentials = 49,
  insufficient_access_rights = 50,
  unavailable = 52,
  unwilling_to_perform = 53,
  not_allowed_on_non_leaf = 66,
  object_class_violation = 65,
  entry_already_exists = 68,
  assertion_failed = 122,
};

struct Control {
  std::string oid;
  bool critical = false;
  std::optional<std::string> value;
};

struct BindRequest {
  std::int64_t version = 0;
  std::string name;
  // Nothing for anything but simple: SASL is refused by what answers this.
  std::optional<Secret> password;
};

struct UnbindRequest {};

enum class Scope : int { base = 0, one = 1, subtree = 2 };

struct SearchRequest {
  std::string base;
  Scope scope = Scope::base;
  std::int64_t size_limit = 0;
  std::int64_t time_limit = 0;
  bool types_only = false;
  Filter filter;
  std::vector<std::string> attributes;
};

struct Attribute {
  std::string type;
  std::vector<std::string> values;
};

enum class ModifyOperation : int { add = 0, remove = 1, replace = 2 };

struct Change {
  ModifyOperation operation = ModifyOperation::replace;
  Attribute attribute;
};

struct ModifyRequest {
  std::string object;
  std::vector<Change> changes;
};

struct AddRequest {
  std::string entry;
  std::vector<Attribute> attributes;
};

struct DeleteRequest {
  std::string entry;
};

struct ModifyDnRequest {
  std::string entry;
  std::string new_rdn;
  bool delete_old = false;
  std::optional<std::string> new_superior;
};

struct CompareRequest {
  std::string entry;
  std::string attribute;
  std::string value;
};

struct AbandonRequest {
  std::int64_t id = 0;
};

struct ExtendedRequest {
  std::string oid;
  std::optional<std::string> value;
};

using Request = std::variant<BindRequest, UnbindRequest, SearchRequest, ModifyRequest, AddRequest, DeleteRequest, ModifyDnRequest, CompareRequest,
                             AbandonRequest, ExtendedRequest>;

struct Message {
  std::int64_t id = 0;
  Request request;
  std::vector<Control> controls;
};

// One whole LDAPMessage. Nothing for what is not one, or holds a request that is not well formed.
std::optional<Message> parse_message(ber::Bytes bytes);

// The paged results control's value (RFC 2696): a size, and the cookie.
struct PagedResults {
  std::int64_t size = 0;
  std::string cookie;
};
std::optional<PagedResults> parse_paged_results(std::string_view value);
std::string encode_paged_results(const PagedResults& paged);

// Password Modify's request value (RFC 3062), each part present or not.
struct PasswordModify {
  std::optional<std::string> user;
  std::optional<Secret> old_password;
  std::optional<Secret> new_password;
};
std::optional<PasswordModify> parse_password_modify(std::string_view value);

// The responses.
struct Result {
  ResultCode code = ResultCode::success;
  std::string matched;
  std::string message;
};

enum class ResponseOp : std::uint8_t {
  bind = 0x61,
  search_done = 0x65,
  modify = 0x67,
  add = 0x69,
  remove = 0x6B,
  modify_dn = 0x6D,
  compare = 0x6F,
};

std::string encode_result(std::int64_t id, ResponseOp op, const Result& result, const std::vector<Control>& controls = {});
std::string encode_search_entry(std::int64_t id, std::string_view dn, const std::vector<Attribute>& attributes);
// An extended response; with id 0 and the Notice of Disconnection's OID, the unsolicited one.
std::string encode_extended(std::int64_t id, const Result& result, const std::optional<std::string>& oid = std::nullopt,
                            const std::optional<std::string>& value = std::nullopt);

}  // namespace lugh::ldap

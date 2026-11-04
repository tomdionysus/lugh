//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "lugh/core/outcome.h"

// What a scope is (TODO/2026-11-04-oauth.md, "The scope model"). A scope is one word of
// RFC 6749 section 3.3's grammar, and one of four kinds: Lugh's own (`lugh:<area>.<verb>`),
// OIDC's names, an application's (`<prefix>:<name>`), or a topic scope for Lir
// (`lir:<action>:<filter>`, lugh/scopes/topic_scope.h). The prefix, the text before the
// first ':', says which application a scope belongs to, so a token for one audience never
// carries another's.
namespace lugh::scopes {

// Lugh's own. A name never changes meaning once shipped: an OAuth client is granted these
// by name.
inline constexpr const char* kDirectoryRead = "lugh:directory.read";
inline constexpr const char* kDirectoryWrite = "lugh:directory.write";
// Enrolment links, and removing or resetting a user's factors: what lets someone into an
// account, apart from changing who is in it.
inline constexpr const char* kCredentialsWrite = "lugh:credentials.write";
// Assurance levels, and which group holds which scope.
inline constexpr const char* kPoliciesWrite = "lugh:policies.write";
inline constexpr const char* kAuditRead = "lugh:audit.read";
// Registering, changing and removing applications, their access and secrets.
inline constexpr const char* kAppsWrite = "lugh:apps.write";

inline constexpr std::string_view kLughPrefix = "lugh";

// Every Lugh scope, in a fixed order.
std::vector<std::string> lugh_scopes();

// The OIDC scopes a person may ask for: openid, profile, email, groups, offline_access.
std::vector<std::string> oidc_scopes();

enum class Kind { lugh, oidc, application, topic };

// The longest scope Lugh grants. A topic filter is the long one; a token over its own cap
// is refused when issued, which is what keeps tokens small.
inline constexpr std::size_t kMostScopeBytes = 1024;

// One word of RFC 6749 section 3.3: printable ASCII, no space, '"' or '\\', not empty, at most
// kMostScopeBytes.
bool well_formed(std::string_view scope);

// The text before the first ':', or nothing for a scope without one (an OIDC name).
std::optional<std::string_view> prefix_of(std::string_view scope);

// An application's scope prefix: a lower-case letter, then lower-case letters, digits and
// '-', at most 32. Chosen at registration (O3) and never changed.
bool valid_prefix(std::string_view prefix);

// The kind of a scope Lugh may grant, or why not: refused for something malformed, a
// Lugh scope Lugh does not have, a word that is neither an OIDC name nor prefixed, or a
// topic scope that does not decode (topic_scope.h). Whether an application's prefix is
// registered is the applications' to say (O3), not this.
Outcome<Kind> grantable(std::string_view scope);

// A space-delimited list, as OAuth's `scope` parameter carries it, split into words; one
// or more spaces between them. Answers nothing when a word is not well formed.
std::optional<std::vector<std::string>> split(std::string_view text);

// The words, sorted and each once, joined with single spaces.
std::string join(std::vector<std::string> scopes);

// The union of several sets, sorted, each once.
std::vector<std::string> united(std::vector<std::string> scopes);

}  // namespace lugh::scopes

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string>
#include <vector>

namespace lugh::api {

// What a caller may do through /api/v1. Vocabulary: an OAuth client is granted these by
// name (P6), so a name never changes meaning once shipped.
inline constexpr const char* kDirectoryRead = "lugh:directory.read";
inline constexpr const char* kDirectoryWrite = "lugh:directory.write";
// Enrolment links, and removing or resetting a user's factors: what lets someone into an
// account, apart from changing who is in it.
inline constexpr const char* kCredentialsWrite = "lugh:credentials.write";
inline constexpr const char* kPoliciesWrite = "lugh:policies.write";
inline constexpr const char* kAuditRead = "lugh:audit.read";

inline std::vector<std::string> all_scopes() { return {kDirectoryRead, kDirectoryWrite, kCredentialsWrite, kPoliciesWrite, kAuditRead}; }

}  // namespace lugh::api

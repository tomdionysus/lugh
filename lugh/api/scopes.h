//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string>
#include <vector>

#include "lugh/scopes/scope.h"

namespace lugh::api {

// What a caller may do through /api/v1: Lugh's own scopes, which lugh/scopes/scope.h holds.
using scopes::kAppsWrite;
using scopes::kAuditRead;
using scopes::kCredentialsWrite;
using scopes::kDirectoryRead;
using scopes::kDirectoryWrite;
using scopes::kKeysWrite;
using scopes::kPoliciesWrite;
using scopes::kSessionsWrite;

inline std::vector<std::string> all_scopes() { return scopes::lugh_scopes(); }

}  // namespace lugh::api

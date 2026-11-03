//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <array>
#include <string_view>

namespace lugh::store {

// Every table, as docs/architecture.md names them. The directory gives them their indexes
// as it arrives (P4); until then they open with none.
inline constexpr std::array<std::string_view, 14> kTables{
    "users",      "credentials", "factors",  "app_passwords", "groups",       "memberships", "apps",
    "app_access", "consents",    "sessions", "grants",        "signing_keys", "policies",    "audit",
};

}  // namespace lugh::store

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "dannan/config/config.h"

namespace lugh::system {

// The process environment, from outside, so the configuration and the keyring are tested
// without setting variables on the test process. Dannan's port; the process's own is
// dannan::config::process_environment(), reached only from the composition root.
using Environment = dannan::config::Environment;

}  // namespace lugh::system

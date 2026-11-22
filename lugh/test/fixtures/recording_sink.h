//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "dannan/test/fixtures/recording_sink.h"

// The stack's one capture sink, Dannan's, for tests about what the node logs: every record at
// every level, with its scope.
using RecordingSink = dannan::test::RecordingSink;

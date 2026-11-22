//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "dannan/contract/completion.h"

// Lugh's asynchronous operations take the stack's shape, Dannan's (contract/completion.h; the
// maintainer: "Lugh goes callback style"): the operation's arguments, then a deadline, the
// caller's executor and `done`, posted to that executor exactly once and never inline.
namespace lugh {

using dannan::contract::answer_now;
using dannan::contract::Deadline;
using dannan::contract::Executor;

template <typename T>
using Done = dannan::contract::Done<T>;

template <typename T>
using Completion = dannan::contract::Completion<T>;

}  // namespace lugh

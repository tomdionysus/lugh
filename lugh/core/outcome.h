//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "dannan/contract/completion.h"

// The stack's one Fault and Outcome, Dannan's (contract/completion.h): a caller branches on a
// Fault the same way whichever system of the stack answered. The API maps each to a status and
// an error code (lugh/api/api_support.h), so a new kind is taken with care.
namespace lugh {

using dannan::contract::Fault;
using dannan::contract::fault_name;
using dannan::contract::Nothing;

template <typename T = Nothing>
using Outcome = dannan::contract::Outcome<T>;

// Neither yes nor no: the request was not decided, because something failed, could not be
// reached, did not answer in time or was cancelled. A caller says so, never that it was refused.
constexpr bool undecided(Fault fault) noexcept {
  return fault == Fault::failed || fault == Fault::unavailable || fault == Fault::timed_out || fault == Fault::cancelled;
}

}  // namespace lugh

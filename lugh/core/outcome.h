//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string>
#include <utility>

namespace lugh {

// Why a request about the directory or a credential was refused. Vocabulary for the API,
// which maps each to a status and an error code (P5), so a new one is added with care.
enum class Fault {
  none,
  // No such user, group, factor or link; or one that was removed.
  not_found,
  // Not at the version the caller expected.
  conflict,
  // A name or email another record already has.
  duplicate,
  // A value out of bounds or of the wrong shape. The message says what was wanted.
  invalid,
  // Understood, and not allowed: a disabled account, a spent link, the last factor.
  refused,
  // The store, the keys or the randomness failed; nothing was changed that is not undone.
  failed,
};

struct Nothing {};

// A Result with a reason a program can act on.
template <typename T = Nothing>
struct Outcome {
  Fault fault = Fault::none;
  std::string message;
  T value{};

  bool ok() const { return fault == Fault::none; }

  static Outcome success(T value = T{}) { return Outcome{Fault::none, {}, std::move(value)}; }
  static Outcome failure(Fault fault, std::string message) { return Outcome{fault, std::move(message), T{}}; }

  // The same refusal, for an Outcome of another type.
  template <typename U>
  static Outcome from(const Outcome<U>& other) {
    return failure(other.fault, other.message);
  }
};

}  // namespace lugh

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// Lugh's callback vocabulary is the stack's, Dannan's contract/completion.h, whose own suite
// tests Completion, answer_now and Outcome. What Lugh adds is tested here: that its names are
// Dannan's types, not copies, so a dependant passes one where the other is asked; and which
// faults leave a request undecided.

#include <gtest/gtest.h>

#include <type_traits>

#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"

TEST(Vocabulary, LughsNamesAreDannansTypes) {
  static_assert(std::is_same_v<lugh::Fault, dannan::contract::Fault>);
  static_assert(std::is_same_v<lugh::Nothing, dannan::contract::Nothing>);
  static_assert(std::is_same_v<lugh::Outcome<>, dannan::contract::Outcome<dannan::contract::Nothing>>);
  static_assert(std::is_same_v<lugh::Outcome<int>, dannan::contract::Outcome<int>>);
  static_assert(std::is_same_v<lugh::Completion<int>, dannan::contract::Completion<int>>);
  static_assert(std::is_same_v<lugh::Done<int>, dannan::contract::Done<int>>);
  static_assert(std::is_same_v<lugh::Executor, dannan::contract::Executor>);
  static_assert(std::is_same_v<lugh::Deadline, dannan::contract::Deadline>);
  const dannan::contract::Outcome<int> theirs = lugh::Outcome<int>::failure(lugh::Fault::timed_out, "late");
  EXPECT_EQ(theirs.fault, dannan::contract::Fault::timed_out);
}

// Failed, unavailable, timed out and cancelled leave a request undecided: the caller says it could
// not be answered, never that it was refused or that the thing is absent.
TEST(Vocabulary, OnlyFailedUnavailableTimedOutAndCancelledAreUndecided) {
  using lugh::Fault;
  for (const auto fault : {Fault::failed, Fault::unavailable, Fault::timed_out, Fault::cancelled})
    EXPECT_TRUE(lugh::undecided(fault)) << lugh::fault_name(fault);
  for (const auto fault : {Fault::none, Fault::not_found, Fault::conflict, Fault::duplicate, Fault::invalid, Fault::refused})
    EXPECT_FALSE(lugh::undecided(fault)) << lugh::fault_name(fault);
}

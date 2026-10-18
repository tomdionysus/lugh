#include "core/secret.h"

#include <gtest/gtest.h>

#include <string>
#include <type_traits>

using lugh::Secret;

// The point of the type: a Secret is not a string and does not become one, so the compiler
// refuses the ways a secret reaches a log line.
static_assert(!std::is_convertible_v<Secret, std::string>);
static_assert(!std::is_convertible_v<std::string, Secret>);
static_assert(!std::is_constructible_v<std::string, Secret>);

TEST(Secret, RevealIsTheOnlyWayToTheBytes) {
  const Secret secret("hunter2");
  EXPECT_EQ(secret.reveal(), "hunter2");
  EXPECT_EQ(secret.size(), 7u);
  EXPECT_FALSE(secret.empty());
  EXPECT_TRUE(Secret().empty());
}

TEST(Secret, EqualsComparesTheBytes) {
  EXPECT_TRUE(Secret("abc").equals(Secret("abc")));
  EXPECT_FALSE(Secret("abc").equals(Secret("abd")));
  EXPECT_FALSE(Secret("abc").equals(Secret("abcd")));
  EXPECT_TRUE(Secret().equals(Secret()));
  EXPECT_FALSE(Secret().equals(Secret("a")));
}

TEST(Secret, CopiesAndMovesKeepTheValue) {
  Secret original("key material");
  Secret copy = original;
  EXPECT_EQ(copy.reveal(), "key material");
  EXPECT_EQ(original.reveal(), "key material");

  Secret moved = std::move(original);
  EXPECT_EQ(moved.reveal(), "key material");
  EXPECT_TRUE(original.empty());  // NOLINT(bugprone-use-after-move): that it is empty is the point

  Secret assigned;
  assigned = copy;
  EXPECT_EQ(assigned.reveal(), "key material");

  Secret move_assigned;
  move_assigned = std::move(copy);
  EXPECT_EQ(move_assigned.reveal(), "key material");
  EXPECT_TRUE(copy.empty());  // NOLINT(bugprone-use-after-move)
}

TEST(Secret, TheRedactionIsWhatALogMaySay) { EXPECT_STREQ(Secret::kRedacted, "[redacted]"); }

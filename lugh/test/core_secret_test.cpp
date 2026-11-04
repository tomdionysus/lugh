//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <string>
#include <type_traits>

#include "lugh/core/secret.h"

// Secret is Dannan's, tested there. What is here is Lugh's text on either side of it.
using lugh::Secret;
using lugh::secret_text;
using lugh::text_secret;

// The point of the type: a Secret is not a string and does not become one, so the compiler
// refuses the ways a secret reaches a log line.
static_assert(!std::is_convertible_v<Secret, std::string>);
static_assert(!std::is_convertible_v<std::string, Secret>);
static_assert(!std::is_constructible_v<std::string, Secret>);
static_assert(!std::is_copy_constructible_v<Secret>);

TEST(Secret, TextInAndOut) {
  const auto secret = text_secret("hunter2");
  EXPECT_EQ(secret_text(secret), "hunter2");
  EXPECT_EQ(secret.size(), 7u);
  EXPECT_EQ(text_secret("").size(), 0u);
  EXPECT_EQ(secret_text(Secret()), "");
}

TEST(Secret, TextComparesAsItsBytes) {
  EXPECT_TRUE(text_secret("abc") == text_secret("abc"));
  EXPECT_FALSE(text_secret("abc") == text_secret("abd"));
  EXPECT_FALSE(text_secret("abc") == text_secret("abcd"));
}

TEST(Secret, TheRedactionIsWhatALogMaySay) { EXPECT_EQ(lugh::kRedacted, "[redacted]"); }

TEST(Secret, BuiltACharacterAtATime) {
  lugh::SecureBuffer typed;
  for (const char c : std::string("typed")) typed.push_back(static_cast<unsigned char>(c));
  const Secret secret(std::move(typed));
  EXPECT_EQ(secret_text(secret), "typed");
}

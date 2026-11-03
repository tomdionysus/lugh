//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/core/secure_bytes.h"
#include "lugh/crypto/compare.h"

using lugh::byte_span;
using lugh::crypto::equal;

TEST(Compare, EqualIsEqual) {
  EXPECT_TRUE(equal(byte_span("abc"), byte_span("abc")));
  EXPECT_TRUE(equal({}, {}));
}

TEST(Compare, AnyDifferenceIsUnequal) {
  EXPECT_FALSE(equal(byte_span("abc"), byte_span("abd")));
  EXPECT_FALSE(equal(byte_span("abc"), byte_span("bbc")));
  EXPECT_FALSE(equal(byte_span("abc"), byte_span("abcd")));
  EXPECT_FALSE(equal(byte_span(""), byte_span("a")));
}

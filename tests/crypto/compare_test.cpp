#include "crypto/compare.h"

#include <gtest/gtest.h>

#include "core/secure_bytes.h"

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

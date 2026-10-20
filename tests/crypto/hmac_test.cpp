#include "crypto/hmac.h"

#include <gtest/gtest.h>

#include "helpers/hex.h"

using lugh::byte_span;
using lugh::crypto::hmac;
using lugh::crypto::HmacDigest;

// RFC 2202, test cases 1 and 2.
TEST(Hmac, Sha1KnownAnswers) {
  const auto one = hmac(HmacDigest::sha1, repeated(0x0b, 20), byte_span("Hi There"));
  ASSERT_TRUE(one.ok);
  EXPECT_EQ(to_hex(one.value), "b617318655057264e28bc0b6fb378c8ef146be00");

  const auto two = hmac(HmacDigest::sha1, byte_span("Jefe"), byte_span("what do ya want for nothing?"));
  ASSERT_TRUE(two.ok);
  EXPECT_EQ(to_hex(two.value), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}

// RFC 4231, test cases 1 and 2.
TEST(Hmac, Sha256KnownAnswers) {
  const auto one = hmac(HmacDigest::sha256, repeated(0x0b, 20), byte_span("Hi There"));
  ASSERT_TRUE(one.ok);
  EXPECT_EQ(to_hex(one.value), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  const auto two = hmac(HmacDigest::sha256, byte_span("Jefe"), byte_span("what do ya want for nothing?"));
  ASSERT_TRUE(two.ok);
  EXPECT_EQ(to_hex(two.value), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(Hmac, RefusesAnEmptyKey) { EXPECT_FALSE(hmac(HmacDigest::sha256, {}, byte_span("x")).ok); }

//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/authn/challenges.h"

using lugh::authn::Challenges;

namespace {

class ChallengesTest : public ::testing::Test {
 protected:
  dannan::test::SteppedTime time;
};

}  // namespace

TEST_F(ChallengesTest, AChallengeIsClaimedOnce) {
  Challenges challenges(time);
  const auto challenge = challenges.issue("visitor");
  EXPECT_EQ(challenge.size(), Challenges::kBytes);
  EXPECT_NE(challenges.issue("visitor"), challenge) << "fresh each time";
  EXPECT_TRUE(challenges.claim(challenge, "visitor"));
  EXPECT_FALSE(challenges.claim(challenge, "visitor")) << "a second submission of one ceremony";
}

TEST_F(ChallengesTest, AFailedCeremonyGivesItsChallengeBack) {
  Challenges challenges(time);
  const auto challenge = challenges.issue("visitor");
  ASSERT_TRUE(challenges.claim(challenge, "visitor"));
  challenges.release(challenge);
  EXPECT_TRUE(challenges.claim(challenge, "visitor"));
}

TEST_F(ChallengesTest, OnlyForTheVisitorItWasIssuedTo) {
  Challenges challenges(time);
  const auto challenge = challenges.issue("visitor");
  EXPECT_FALSE(challenges.claim(challenge, "another visitor"));
  EXPECT_FALSE(challenges.claim(challenge, "visito")) << "a prefix of the binding is not the binding";
  EXPECT_TRUE(challenges.claim(challenge, "visitor"));
}

TEST_F(ChallengesTest, OnlyItsOwnAndOnlyWhole) {
  Challenges challenges(time);
  Challenges elsewhere(time);
  EXPECT_FALSE(challenges.claim(elsewhere.issue("visitor"), "visitor")) << "another process's key";
  auto bent = challenges.issue("visitor");
  bent[0] ^= 0x01;
  EXPECT_FALSE(challenges.claim(bent, "visitor"));
  auto later = challenges.issue("visitor");
  later[20] ^= 0x01;
  EXPECT_FALSE(challenges.claim(later, "visitor")) << "an expiry moved";
  EXPECT_FALSE(challenges.claim(challenges.issue("visitor").substr(1), "visitor"));
  EXPECT_FALSE(challenges.claim("", "visitor"));
}

TEST_F(ChallengesTest, AChallengeExpires) {
  Challenges challenges(time, std::chrono::minutes(5));
  const auto challenge = challenges.issue("visitor");
  time.advance(std::chrono::minutes(5));
  EXPECT_FALSE(challenges.claim(challenge, "visitor"));
  const auto fresh = challenges.issue("visitor");
  time.advance(std::chrono::minutes(4));
  EXPECT_TRUE(challenges.claim(fresh, "visitor"));
}

// Full of live claims, a new one is refused rather than forgetting one that could be replayed;
// once they expire there is room again.
TEST_F(ChallengesTest, TheUsedSetIsBounded) {
  Challenges challenges(time, std::chrono::minutes(5), 2);
  ASSERT_TRUE(challenges.claim(challenges.issue("a"), "a"));
  ASSERT_TRUE(challenges.claim(challenges.issue("b"), "b"));
  const auto third = challenges.issue("c");
  EXPECT_FALSE(challenges.claim(third, "c"));
  time.advance(std::chrono::minutes(4));
  const auto fourth = challenges.issue("d");
  time.advance(std::chrono::minutes(2));
  EXPECT_TRUE(challenges.claim(fourth, "d")) << "the first two have expired";
}

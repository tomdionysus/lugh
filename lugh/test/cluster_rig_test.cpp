//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// P8.0: the rigs P8's components move onto, Dagda's in-process cluster opening Lugh's spaces.
// What each later step relies on: a commit is the committing node's head at once, a peer is
// told of it by the change notice, and a node keeps what it committed across a restart and
// catches up on what it missed while down (P8 plan, "Derived indexes and caches").

#include "lugh/test/fixtures/cluster_rig.h"

#include <gtest/gtest.h>

namespace {

TEST(ClusterRig, OneNodeOpensBothOfLughsSpaces) {
  ClusterRig rig(1);
  EXPECT_TRUE(rig.head(0, kScopeSpace).has_value());
  EXPECT_TRUE(rig.head(0, kSecretsSpace).has_value());
  EXPECT_NE(rig.space(0, kScopeSpace), rig.space(0, kSecretsSpace));
}

TEST(ClusterRig, ACommitIsTheCommittingNodesHeadAtOnce) {
  ClusterRig rig(1);
  const auto secrets_before = rig.head(0, kSecretsSpace);

  const auto put = rig.put(0, kScopeSpace, "user/alice", "v1");
  ASSERT_TRUE(put.finished) << put.why;
  ASSERT_TRUE(put.outcome);

  const auto head = rig.head(0, kScopeSpace);
  ASSERT_TRUE(head);
  EXPECT_EQ(head->generation, put.outcome->record.generation);
  EXPECT_EQ(head->hash, put.outcome->record.hash);
  EXPECT_EQ(rig.value(0, kScopeSpace, "user/alice"), "v1");
  // One space's commit leaves the other alone.
  EXPECT_EQ(rig.head(0, kSecretsSpace), secrets_before);
  EXPECT_EQ(rig.value(0, kSecretsSpace, "user/alice"), std::nullopt);
}

TEST(ClusterRig, ACommitOnOneNodeReachesTheOtherTwo) {
  ClusterRig rig(3);
  const auto put = rig.put(0, kScopeSpace, "user/alice", "v1");
  ASSERT_TRUE(put.finished) << put.why;
  ASSERT_TRUE(put.outcome);
  const auto generation = put.outcome->record.generation;

  for (size_t i : {1U, 2U}) {
    ASSERT_TRUE(rig.reaches(i, kScopeSpace, generation)) << rig.node(i).name();
    EXPECT_EQ(rig.head(i, kScopeSpace), rig.head(0, kScopeSpace)) << rig.node(i).name();
    EXPECT_EQ(rig.value(i, kScopeSpace, "user/alice"), "v1") << rig.node(i).name();
  }
}

TEST(ClusterRig, ARestartedNodeKeepsWhatItCommitted) {
  ClusterRig rig(1);
  const auto put = rig.put(0, kSecretsSpace, "credential/alice", "hash");
  ASSERT_TRUE(put.finished) << put.why;
  const auto before = rig.head(0, kSecretsSpace);

  rig.node(0).restart();

  EXPECT_EQ(rig.head(0, kSecretsSpace), before);
  EXPECT_EQ(rig.value(0, kSecretsSpace, "credential/alice"), "hash");
}

TEST(ClusterRig, ANodeDownForACommitCatchesUpWhenItReturns) {
  ClusterRig rig(3);
  rig.node(2).stop();
  ASSERT_TRUE(rig.cluster.dead_to(rig.node(0), rig.node(2).id()));

  const auto put = rig.put(0, kScopeSpace, "user/bob", "v1");
  ASSERT_TRUE(put.finished) << put.why;
  ASSERT_TRUE(put.outcome);
  ASSERT_TRUE(rig.reaches(1, kScopeSpace, put.outcome->record.generation));

  // Brought up to date by its maintenance, not by a notice; the bound is Dagda's own case's
  // (heads_exchange_test, a returning holder).
  rig.node(2).start();
  ASSERT_TRUE(rig.reaches(2, kScopeSpace, put.outcome->record.generation, std::chrono::seconds(30)));
  EXPECT_EQ(rig.value(2, kScopeSpace, "user/bob"), "v1");
}

}  // namespace

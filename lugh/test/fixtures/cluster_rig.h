//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "dagda/test/fixtures/cluster.h"
#include "dagda/test/fixtures/heads_space.h"
#include "dagda/test/fixtures/tree.h"

// Lugh's two replicated spaces (P8 plan, "Where each table goes").
inline constexpr std::string_view kScopeSpace = "lugh/scope";
inline constexpr std::string_view kSecretsSpace = "lugh/secrets";

// Nodes of Dagda's in-process cluster, each opening Lugh's spaces: what P8 moves each
// component onto, beside AuthnRig's MemoryStore. One node for a component's own behaviour,
// three for what a cluster changes. Until a component brings Lugh's codec and merge (P8.3 on),
// the spaces are Dagda's neutral owner's, and a record is a note on the head.
class ClusterRig {
 public:
  // The first node founds the spaces and the rest join, as a deployed cluster is made: no node
  // but a founder forms a space alone. Maintenance runs as on a deployed node, on a short
  // interval, since it is what brings a returning node up to date; the change notice reaches
  // only the nodes present at the commit.
  explicit ClusterRig(size_t nodes) {
    for (size_t i = 0; i < nodes; ++i) {
      dagda::test::ClusterNodeOptions options;
      options.spaces.push_back(dagda::test::founded_spec(std::string(kScopeSpace)));
      options.spaces.push_back(dagda::test::founded_spec(std::string(kSecretsSpace)));
      options.exchange.joiner = i > 0;
      options.maintenance.automatic = true;
      options.maintenance.interval = std::chrono::milliseconds(25);
      options.maintenance.gc_interval = std::chrono::hours(1);
      cluster.add("lugh-" + std::to_string(i + 1), options);
    }
    cluster.start_all();
    EXPECT_TRUE(cluster.converged());
  }

  dagda::test::ClusterNode& node(size_t i) { return cluster[i]; }
  dagda::heads::SpaceId space(size_t i, std::string_view name) { return node(i).api().heads().id_of(name); }

  // Commits `key` = `value` on node i, on that node alone; the peers are owed it.
  dagda::MutationEvidence put(size_t i, std::string_view space_name, const std::string& key, const std::string& value) {
    return node(i).api().heads().mutate_delta(
        space(i, space_name), dagda::test::neutral_mutation([key, value](dagda::test::NeutralEditing& editing) { editing.set_note(key, value); }), kDeadline);
  }

  // Node i's committed head of a space, read from what the node holds; empty when it has none.
  // current() would not do: it reads nothing, so a head not yet decoded (after founding, a
  // restart or a peer's commit) answers an empty view.
  std::optional<dagda::heads::HeadIdentity> head(size_t i, std::string_view space_name) {
    const auto read = local(i, space_name);
    if (!read.finished || !read.view) return std::nullopt;
    return dagda::heads::HeadIdentity{read.view->generation, read.view->hash};
  }

  // A record in node i's view of a space; empty when it holds none.
  std::optional<std::string> value(size_t i, std::string_view space_name, const std::string& key) {
    const auto read = local(i, space_name);
    if (!read.finished || !read.view || !read.view->state) return std::nullopt;
    const auto& notes = dagda::test::NeutralCodec::as_head(read.view->state)->notes.get();
    const auto found = notes.find(key);
    if (found == notes.end()) return std::nullopt;
    return found->second;
  }

  // Waits for node i's head of a space to reach `generation`, told by its change notice; false
  // when it has not within the bound, which is a safety net against a hang, not a timing.
  bool reaches(size_t i, std::string_view space_name, uint64_t generation, std::chrono::milliseconds within = kDeadline) {
    struct Reached {
      std::atomic<bool> told{false};
      std::promise<void> promise;
      void tell() {
        if (!told.exchange(true)) promise.set_value();
      }
    };
    auto reached = std::make_shared<Reached>();
    auto future = reached->promise.get_future();
    const auto id = space(i, space_name);
    auto& heads = node(i).api().heads();
    const auto watch = heads.watch(id, cluster.io().context.get_executor(), [reached, generation](dagda::heads::HeadMoved moved) {
      if (moved.after.generation >= generation) reached->tell();
    });
    if (!watch.watching) {
      ADD_FAILURE() << "no watch on " << space_name << ": " << watch.why;
      return false;
    }
    // The head may have moved before the watch began.
    const auto now = head(i, space_name);
    if (now && now->generation >= generation) reached->tell();
    const bool ok = future.wait_for(within) == std::future_status::ready;
    heads.unwatch(id, watch.token);
    return ok;
  }

  static constexpr std::chrono::milliseconds kDeadline{std::chrono::seconds(10)};
  dagda::test::Cluster cluster;

 private:
  dagda::HeadReadEvidence local(size_t i, std::string_view space_name) {
    return node(i).api().heads().read(space(i, space_name), dagda::HeadRead::local, kDeadline);
  }
};

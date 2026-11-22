//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What arrives as a scope, from a grant written through the API or an OAuth `scope`
// parameter: the space-delimited list, each word's kind, and a topic scope's grammar. A topic
// scope that decodes must encode back to a scope that decodes to the same thing.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "lugh/client/scopes.h"
#include "lugh/fuzz/target.h"
#include "lugh/scopes/scope.h"

namespace {

int run(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::scopes;
  const std::string input(reinterpret_cast<const char*>(data), size);

  (void)grantable(input);
  if (const auto words = split(input)) {
    for (const auto& word : *words) {
      if (!well_formed(word)) lugh::fuzz::finding("a split word that is not well formed");
      (void)grantable(word);
    }
    (void)join(*words);
  }

  if (const auto topic = decode_topic(input)) {
    const auto encoded = encode_topic(*topic);
    if (!encoded) lugh::fuzz::finding("a topic scope read that cannot be written");
    const auto again = decode_topic(*encoded);
    if (!again || !(*again == *topic)) lugh::fuzz::finding("a topic scope written that does not read back as itself");
  }

  // A broker's parse of the same bytes as a grant: one scope gives at most one grant or refusal.
  const std::string scopes[] = {input};
  const auto grants = lugh::client::TopicGrants::parse(scopes, "alice");
  if (grants.refused().size() + grants.publish().size() + grants.retain().size() + grants.subscribe().size() > 1)
    lugh::fuzz::finding("one scope that gave more than one grant or refusal");
  return 0;
}

const dannan::fuzz::Registration registered(
    "scope", [](std::span<const std::uint8_t> input) { run(input.data(), input.size()); }, [] { return lugh::fuzz::corpus("scope"); });

}  // namespace

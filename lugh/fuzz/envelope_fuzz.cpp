//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A record envelope, as another node's commit carries it: what decodes must encode to the same bytes, and merge with itself
// to itself.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/fuzz/target.h"
#include "lugh/merge/record_merge.h"

namespace {

int run(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::merge;
  const std::span<const unsigned char> bytes(data, size);
  const auto envelope = decode(bytes);
  if (!envelope) return 0;
  const auto again = encode(*envelope);
  if (again.size() != size || !std::equal(again.begin(), again.end(), bytes.begin())) lugh::fuzz::finding("an envelope that does not write back as itself");
  const Records one{{"k", *envelope}};
  if (merge(std::nullopt, {one, one}) != one) lugh::fuzz::finding("an envelope that does not merge with itself to itself");
  return 0;
}

// Made by the writer: an edit with a value, and a tombstone.
std::vector<lugh::fuzz::Bytes> seeds() {
  using namespace lugh::merge;
  Envelope edit;
  edit.version = 3;
  edit.writer = "node-a";
  edit.value = lugh::SecureBuffer(16, 0x55);
  Envelope tombstone;
  tombstone.version = 4;
  tombstone.writer = "node-b";
  tombstone.removed = true;
  const auto first = encode(edit);
  const auto second = encode(tombstone);
  return {lugh::fuzz::Bytes(first.begin(), first.end()), lugh::fuzz::Bytes(second.begin(), second.end())};
}

const dannan::fuzz::Registration registered("envelope", [](std::span<const std::uint8_t> input) { run(input.data(), input.size()); }, seeds);

}  // namespace

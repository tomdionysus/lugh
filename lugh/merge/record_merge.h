//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "lugh/core/secure_bytes.h"

// Lugh's merge for its shared spaces (TODO/2026-11-13-p8-plan.md, "The merge", the maintainer 2026-11-13), as pure functions over a map
// of records, so it is the same on every node and is tested apart from Dagda. A space's state is a map from a record's key
// (`<kind>/<id>`) to its envelope; Dagda's Merge hands this the heads to join.
namespace lugh::merge {

// One record as a space holds it: Lugh's own bytes, the version Lugh gave it (its ETag), the node that wrote that version,
// and whether it is a tombstone. A tombstone keeps no value and is kept for ever.
struct Envelope {
  std::uint64_t version = 0;
  std::string writer;
  bool removed = false;
  SecureBuffer value;

  bool operator==(const Envelope&) const = default;
};

using Records = std::map<std::string, Envelope>;

inline constexpr std::size_t kMostValueBytes = 256 * 1024;
inline constexpr std::size_t kMostWriterBytes = 256;

SecureBuffer encode(const Envelope& envelope);
// Nothing for bytes that are not an envelope Lugh wrote, a tombstone with a value among them.
std::optional<Envelope> decode(std::span<const unsigned char> bytes);

// Which of two envelopes of one key stands: a tombstone over any edit; between two tombstones or two edits, the higher
// version, then the higher writer, so the answer is the same whichever is offered first.
const Envelope& winner(const Envelope& a, const Envelope& b);

// The heads joined: every key any head holds, each the winner of its envelopes. A key absent from a head is one that head
// never had, since a removal is a tombstone, never an absence. The common ancestor changes nothing under these rules (a key
// edited on one side has the higher version there), and is accepted so the shape is Dagda's. Commutative, associative and
// idempotent, so any order of arrival on any node gives the same map.
Records merge(const std::optional<Records>& base, const std::vector<Records>& heads);

// Whether a write of `key` may be made: never once it has a tombstone, since a removed key is never used again.
bool writable(const Records& records, const std::string& key);

// A unique index rebuilt from a space: each value to the live keys that hold it. Two records holding one value (the same
// name made on both sides of a split) are both kept; the value is then ambiguous, and whatever looks up by it (sign-in, an
// LDAP bind) refuses until an administrator renames one.
class UniqueIndex {
 public:
  struct Found {
    std::optional<std::string> key;
    bool ambiguous = false;
  };

  void add(const std::string& value, const std::string& key);
  void remove(const std::string& value, const std::string& key);

  // The one key holding `value`; nothing, and `ambiguous`, when more than one does.
  Found find(const std::string& value) const;
  // Every value more than one key holds, for an administrator to settle.
  std::vector<std::string> ambiguous() const;

 private:
  std::map<std::string, std::set<std::string>> _keys;
};

}  // namespace lugh::merge

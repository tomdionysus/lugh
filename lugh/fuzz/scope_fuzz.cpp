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

#include "lugh/scopes/scope.h"
#include "lugh/scopes/topic_scope.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::scopes;
  const std::string input(reinterpret_cast<const char*>(data), size);

  (void)grantable(input);
  if (const auto words = split(input)) {
    for (const auto& word : *words) {
      if (!well_formed(word)) std::abort();
      (void)grantable(word);
    }
    (void)join(*words);
  }

  if (const auto topic = decode_topic(input)) {
    const auto encoded = encode_topic(*topic);
    if (!encoded) std::abort();
    const auto again = decode_topic(*encoded);
    if (!again || !(*again == *topic)) std::abort();
  }
  return 0;
}

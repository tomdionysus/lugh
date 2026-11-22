//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "dannan/fuzz/fuzz.h"

// Lugh's fuzz targets, one per parser of untrusted bytes, registered with Dannan's harness
// (dannan/fuzz/fuzz.h), so each runs three ways from one source: as a libFuzzer binary (a campaign),
// as a replay over files, and through dannan::fuzz::smoke in lugh_tests on every gate and in CI.
namespace lugh::fuzz {

using Bytes = dannan::net::Bytes;

// What a target says must hold, and did not. A throw, so a finding fails a test in lugh_tests
// rather than the binary; under libFuzzer it is a crash, as std::abort() was.
[[noreturn]] inline void finding(const std::string& what) { throw std::logic_error("fuzz finding: " + what); }

// Every file of a target's committed corpus (lugh/fuzz/corpus/<name>/), in name order, each an input.
std::vector<Bytes> corpus(const std::string& name);

// `selector` then `body`: a seed for a target whose first byte picks the parser.
template <typename Body>
Bytes selected(unsigned char selector, const Body& body) {
  Bytes out{selector};
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

}  // namespace lugh::fuzz

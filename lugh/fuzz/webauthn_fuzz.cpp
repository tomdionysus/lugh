//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What an authenticator sends, through the browser: CBOR (an attestation object, attested
// credential data and its COSE key). An item read from the front ends inside the input, and
// reading those bytes alone gives the same item; whatever decodes is offered as a COSE key.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/webauthn/cbor.h"
#include "lugh/webauthn/cose.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::webauthn;
  const std::span<const std::uint8_t> input(data, size);

  std::size_t used = 0;
  const auto front = cbor::decode(input, &used);
  if (front) {
    if (used == 0 || used > size) std::abort();
    const auto alone = cbor::decode(input.first(used));
    if (!alone) std::abort();
    (void)public_key(*front);
  }

  const auto whole = cbor::decode(input);
  if (whole && (!front || used != size)) std::abort();
  return 0;
}
